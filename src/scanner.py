"""ProofCRA Core Scanner — Deterministic-first EU CRA / NIS2 vulnerability & reachability engine.

Pipeline:
  1. Anchore Syft            -> CycloneDX SBOM (sbom.cdx.json)
  2. Google OSV-Scanner v2.7 -> Dependency vulnerability extraction
  3. CISA KEV + ENISA EUVD   -> Active-exploitation filter (EU CRA Art. 14 24h clock)
  4. Tier-2 Static AST/JS    -> Deterministic reachability proof (zero LLM tokens)
  5. Gemini 3.8 Flash        -> Structured ENISA SRP compliance dossier (only when findings exist
                                and GEMINI_API_KEY is configured; deterministic fallback otherwise)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from feeds import ThreatIntelClient
from models import (
    CraReport,
    EnisaCraDossier,
    LlmTokenUsage,
    RegulatoryRegime,
    ScanSummary,
    VulnerabilityFinding,
)
from reachability import analyze_reachability

CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
FORBIDDEN_MODEL_PREFIXES = ("gemini-2.0", "gemini-2.5", "gemini-1.")


def _run_cmd(cmd: list[str], allow_exit_codes: set[int] | None = None) -> subprocess.CompletedProcess[str]:
    allowed = allow_exit_codes or {0}
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode not in allowed:
        raise RuntimeError(
            f"Command failed (exit {proc.returncode}): {' '.join(cmd)}\n"
            f"STDERR:\n{proc.stderr.strip()}"
        )
    return proc


SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


def _detect_tool_versions() -> dict[str, str]:
    versions: dict[str, str] = {"proofcra_core": "0.1.0-phase1"}
    try:
        proc = subprocess.run(["syft", "version"], capture_output=True, text=True, check=False)
        syft_ver = "unknown"
        for line in (proc.stdout or proc.stderr).splitlines():
            if line.strip().lower().startswith("version:"):
                syft_ver = line.split(":", 1)[1].strip()
                break
        versions["syft"] = syft_ver
    except FileNotFoundError:
        versions["syft"] = "not-installed"

    try:
        proc = subprocess.run(["osv-scanner", "--version"], capture_output=True, text=True, check=False)
        osv_ver = "unknown"
        for line in (proc.stdout or proc.stderr).splitlines():
            if "osv-scanner version:" in line.lower():
                osv_ver = line.split(":", 1)[1].strip()
                break
        versions["osv_scanner"] = osv_ver
    except FileNotFoundError:
        versions["osv_scanner"] = "not-installed"
    return versions


def _generate_sbom(target: Path, sbom_path: Path) -> int:
    """Run Anchore Syft to generate a CycloneDX JSON SBOM and return component count."""
    _run_cmd(["syft", f"dir:{target}", "-o", f"cyclonedx-json={sbom_path}"], allow_exit_codes={0})
    sbom_data = json.loads(sbom_path.read_text(encoding="utf-8"))
    components = sbom_data.get("components", [])
    return len(components) if isinstance(components, list) else 0


def _run_osv_scan(target: Path, sbom_path: Path) -> list[dict[str, Any]]:
    """Run OSV-Scanner v2 against both the CycloneDX SBOM and source lockfiles, then merge."""
    raw_results: list[dict[str, Any]] = []
    scan_invocations = [
        ["osv-scanner", "scan", "source", "--format=json", f"--lockfile={sbom_path}"],
        ["osv-scanner", "scan", "source", "--format=json", str(target)],
    ]

    for cmd in scan_invocations:
        try:
            # OSV-Scanner returns 0 (clean) or 1 (vulnerabilities found); 128 = no packages found
            proc = _run_cmd(cmd, allow_exit_codes={0, 1, 128})
            if proc.stdout.strip():
                parsed = json.loads(proc.stdout)
                if isinstance(parsed, dict) and isinstance(parsed.get("results"), list):
                    raw_results.extend(parsed["results"])
        except Exception as exc:
            print(f"[ProofCRA] Warning: OSV invocation failed ({' '.join(cmd)}): {exc}", file=sys.stderr)

    return raw_results


def _extract_fixed_versions(vuln: dict[str, Any], package_name: str) -> list[str]:
    fixed: list[str] = []
    for affected in vuln.get("affected", []) or []:
        pkg = affected.get("package", {}) or {}
        if pkg.get("name") and pkg.get("name").lower() != package_name.lower():
            continue
        for r in affected.get("ranges", []) or []:
            for ev in r.get("events", []) or []:
                fv = ev.get("fixed")
                if fv and fv not in fixed:
                    fixed.append(str(fv))
    return fixed


def _extract_severity_and_score(vuln: dict[str, Any], group_max_sev: str | None) -> tuple[str, float | None]:
    score: float | None = None
    if group_max_sev:
        try:
            score = float(group_max_sev)
        except ValueError:
            score = None

    db_sev = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(db_sev, str) and db_sev.strip():
        severity = db_sev.strip().upper()
        if severity == "MODERATE":
            severity = "MEDIUM"
    elif score is not None:
        if score >= 9.0:
            severity = "CRITICAL"
        elif score >= 7.0:
            severity = "HIGH"
        elif score >= 4.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"
    else:
        severity = "UNKNOWN"

    return severity, score


def _collect_cve_ids(osv_id: str, aliases: list[str]) -> list[str]:
    cves: list[str] = []
    for candidate in [osv_id, *aliases]:
        for match in CVE_REGEX.findall(str(candidate)):
            upper = match.upper()
            if upper not in cves:
                cves.append(upper)
    return cves


def _build_recommended_action(
    package_name: str,
    ecosystem: str,
    fixed_versions: list[str],
    cra_triggered: bool,
    actively_exploited: bool,
    is_reachable: bool,
) -> str:
    upgrade_hint = (
        f"Upgrade {ecosystem} package '{package_name}' to >= {fixed_versions[0]}."
        if fixed_versions
        else f"Check upstream advisory for '{package_name}' and apply vendor mitigation/workaround."
    )
    if cra_triggered:
        return f"[IMMEDIATE — 24h CRA CLOCK] Initiate ENISA SRP Early Warning review AND {upgrade_hint}"
    if actively_exploited and not is_reachable:
        return (
            f"[VERIFY & PATCH] Actively exploited CVE detected, but Tier-2 static analysis found no direct "
            f"imports/calls. Confirm transitive exposure and {upgrade_hint}"
        )
    if is_reachable:
        return f"[SCHEDULE PATCH] Reachable non-KEV vulnerability. {upgrade_hint}"
    return f"[LOW PRIORITY / NOISE FILTERED] Unreachable non-exploited dependency. {upgrade_hint}"


def _build_deterministic_dossier(
    regime: RegulatoryRegime,
    findings: list[VulnerabilityFinding],
    summary: ScanSummary,
) -> EnisaCraDossier:
    """Deterministic ENISA CRA/NIS2 compliance dossier (zero LLM cost fallback)."""
    triggered = [f for f in findings if f.cra_article14_triggered]
    exploited_unreachable = [
        f for f in findings if f.exploit_intel.actively_exploited and not f.cra_article14_triggered
    ]
    critical_ids: list[str] = []
    for f in triggered or exploited_unreachable or findings[:5]:
        label = f.cve_ids[0] if f.cve_ids else f.osv_id
        if label not in critical_ids:
            critical_ids.append(label)

    if triggered:
        clock_status = "ACTIVE_24H_EARLY_WARNING_REQUIRED"
        affected_desc = "; ".join(
            f"{(f.cve_ids[0] if f.cve_ids else f.osv_id)} in {f.ecosystem}/{f.package_name}@{f.package_version}"
            f"{f' ({f.exploit_intel.euvd_id})' if f.exploit_intel.euvd_id else ''}"
            for f in triggered
        )
        exec_summary = (
            f"URGENT ({regime.value}): {len(triggered)} actively exploited AND statically reachable "
            f"vulnerability(ies) detected ({affected_desc}). Under EU CRA Article 14(2)(a) (enforceable "
            f"since 11 Sept 2026), the 24-hour ENISA Single Reporting Platform (SRP) Early Warning clock "
            f"is triggered upon awareness for in-scope products with digital elements. "
            f"Deterministic triage reduced {summary.total_vulnerabilities} raw dependency alerts by "
            f"{summary.alert_noise_reduction_pct:.1f}%."
        )
        early_warning = (
            f"ENISA SRP — 24-Hour Early Warning Draft (Art. 14(2)(a) EU Regulation 2024/2847)\n"
            f"- Awareness Timestamp (UTC): {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}\n"
            f"- Affected Component(s): {affected_desc}\n"
            f"- Exploitation Signal: Confirmed actively exploited via CISA KEV / ENISA EUVD.\n"
            f"- Reachability Proof: Confirmed reachable in application source/config via ProofCRA Tier-2 analysis.\n"
            f"- Affected EU Member States: [COMPLETE PRIOR TO SUBMISSION — list Member States where product is distributed]\n"
            f"- Preliminary Cross-Border / Malicious Impact Assessment: Under active engineering investigation."
        )
        notification_72h = (
            f"ENISA SRP — 72-Hour Vulnerability Notification Draft (Art. 14(2)(b))\n"
            f"- Technical Scope: {len(triggered)} actively exploited reachable finding(s) verified across "
            f"{summary.total_sbom_components} CycloneDX SBOM component(s).\n"
            f"- Corrective / Mitigating Measures: Upgrade affected packages to patched versions listed in remediation steps, "
            f"regenerate lockfiles and CycloneDX SBOM, and execute regression test suite.\n"
            f"- Vulnerability Details: Attach ProofCRA CycloneDX SBOM and Tier-2 reachability call-site trace."
        )
        customer_notice = (
            f"Security Advisory Draft (CRA Art. 14(8) Customer Notice)\n"
            f"We have identified actively exploited third-party component vulnerability(ies) ({', '.join(critical_ids)}) "
            f"affecting our product. We are preparing an immediate security update. Customers running self-hosted or "
            f"client deployments should restrict external network exposure to affected interfaces immediately and "
            f"apply the patched release as soon as published."
        )
    elif exploited_unreachable:
        clock_status = "URGENT_VERIFICATION_REQUIRED"
        exec_summary = (
            f"ATTENTION ({regime.value}): {len(exploited_unreachable)} actively exploited CVE(s) exist in the "
            f"dependency graph, but Tier-2 static analysis found no direct imports or call sites. Confirm no "
            f"dynamic/transitive invocation path exists before deciding whether an ENISA Art. 14 filing is required."
        )
        early_warning = (
            "No immediate ENISA Early Warning drafted yet: actively exploited CVE(s) appear statically unreachable. "
            "If runtime verification proves exploitability in your shipped product, escalate to 24h Early Warning immediately."
        )
        notification_72h = "Pending runtime reachability confirmation and scheduled dependency upgrade."
        customer_notice = "No immediate customer security notice required unless runtime reachability is confirmed."
    elif findings:
        clock_status = "MONITOR_AND_PATCH"
        exec_summary = (
            f"NO 24H CLOCK TRIGGERED ({regime.value}): {summary.total_vulnerabilities} dependency vulnerability(ies) "
            f"detected, with 0 confirmed active exploits in CISA KEV or ENISA EUVD. Patch reachable vulnerabilities "
            f"during normal security maintenance to maintain CRA Annex I vulnerability-handling compliance."
        )
        early_warning = "Not required — zero actively exploited vulnerabilities detected."
        notification_72h = "Not required — zero actively exploited vulnerabilities detected."
        customer_notice = "Not required for Article 14(8) emergency notice; include fixes in routine release notes."
    else:
        clock_status = "COMPLIANT_NO_ACTIVE_EXPLOITS"
        exec_summary = (
            f"CLEAN SCAN ({regime.value}): 0 known vulnerabilities identified across "
            f"{summary.total_sbom_components} CycloneDX SBOM components. No ENISA reporting obligations triggered."
        )
        early_warning = "Not applicable — zero vulnerabilities detected."
        notification_72h = "Not applicable — zero vulnerabilities detected."
        customer_notice = "Not applicable — zero vulnerabilities detected."

    remediation_steps: list[str] = []
    seen_pkgs: set[str] = set()
    for f in findings:
        key = f"{f.ecosystem}:{f.package_name}"
        if key in seen_pkgs:
            continue
        seen_pkgs.add(key)
        fix_ver = f.fixed_versions[0] if f.fixed_versions else "latest-patched"
        prefix = "[P0 — 24H CRA]" if f.cra_article14_triggered else ("[P1]" if f.reachability.is_potentially_reachable else "[P2]")
        remediation_steps.append(
            f"{prefix} Upgrade {f.ecosystem}/{f.package_name} from {f.package_version} -> {fix_ver} "
            f"({f.cve_ids[0] if f.cve_ids else f.osv_id})."
        )
        if len(remediation_steps) >= 10:
            break

    return EnisaCraDossier(
        regime=regime.value,
        reporting_clock_status=clock_status,
        executive_summary=exec_summary,
        affected_critical_cves=critical_ids,
        early_warning_24h_draft=early_warning,
        vulnerability_notification_72h_draft=notification_72h,
        final_report_14d_checklist=[
            "Confirm patched package versions are locked in package-lock.json / requirements.txt and re-scan with ProofCRA.",
            "Generate updated CycloneDX SBOM verifying 0 remaining actively exploited CVEs.",
            "Document root cause, severity assessment, and exact patch release version/commit SHA.",
            "Confirm CRA Article 14(8) customer advisory was published and distributed to affected users.",
            "Submit Final Report via ENISA Single Reporting Platform (SRP) within 14 days of patch availability.",
        ],
        article_14_8_customer_notice_draft=customer_notice,
        prioritized_remediation_steps=remediation_steps
        or ["Maintain continuous SBOM & OSV monitoring in CI/CD."],
    )


def _run_gemini_triage(
    regime: RegulatoryRegime,
    findings: list[VulnerabilityFinding],
    summary: ScanSummary,
) -> tuple[EnisaCraDossier, str, LlmTokenUsage]:
    """Generate a structured ENISA CRA/NIS2 compliance dossier with automatic 3.8 -> 3.5-flash-lite failover."""
    primary_model = os.environ.get("PROOFCRA_GEMINI_MODEL", "gemini-3.8-flash").strip()
    fallback_raw = os.environ.get("PROOFCRA_GEMINI_FALLBACK_MODELS", "gemini-3.5-flash-lite").strip()
    model_chain = [m.strip() for m in [primary_model, *fallback_raw.split(",")] if m.strip()]
    # Deduplicate preserving order
    model_chain = list(dict.fromkeys(model_chain))

    for model in model_chain:
        if any(model.lower().startswith(bad) for bad in FORBIDDEN_MODEL_PREFIXES):
            raise ValueError(
                f"Model '{model}' violates ProofCRA guardrails. Use gemini-3.8-flash or gemini-3.5-flash-lite."
            )

    thinking_level = os.environ.get("PROOFCRA_THINKING_LEVEL", "low").strip().lower()
    if thinking_level not in {"low", "medium", "high"}:
        thinking_level = "low"

    max_output_tokens = int(os.environ.get("PROOFCRA_MAX_OUTPUT_TOKENS", "4096"))
    per_model_timeout_sec = float(os.environ.get("PROOFCRA_LLM_TIMEOUT_SEC", "20.0"))

    # Keep prompt compact to protect Stage 1 token margins (top 15 prioritized findings)
    compact_findings = [
        {
            "osv_id": f.osv_id,
            "cve_ids": f.cve_ids,
            "euvd_id": f.exploit_intel.euvd_id,
            "package": f"{f.ecosystem}/{f.package_name}@{f.package_version}",
            "severity": f.severity,
            "cvss": f.cvss_score,
            "fixed_versions": f.fixed_versions[:3],
            "in_cisa_kev": f.exploit_intel.in_cisa_kev,
            "kev_date_added": f.exploit_intel.kev_date_added,
            "euvd_exploited": f.exploit_intel.euvd_exploited,
            "euvd_epss": f.exploit_intel.euvd_epss,
            "reachability_status": f.reachability.status.value,
            "is_potentially_reachable": f.reachability.is_potentially_reachable,
            "matched_files": f.reachability.matched_files[:5],
            "call_sites": f.reachability.call_sites[:5],
            "cra_article14_triggered": f.cra_article14_triggered,
            "summary": f.summary[:260],
        }
        for f in findings[:15]
    ]

    system_instruction = (
        "You are ProofCRA's EU cybersecurity compliance analyst specializing in Regulation (EU) 2024/2847 "
        "(Cyber Resilience Act — CRA, Article 14 reporting live since 11 Sept 2026) and NIS2. "
        "Base EVERY claim strictly on the deterministic SBOM, OSV, CISA KEV, ENISA EUVD, and static "
        "reachability evidence provided. Never hallucinate CVEs, file paths, or fixed versions. "
        "Clearly distinguish actively exploited + reachable findings (which trigger the 24h ENISA SRP "
        "Early Warning clock) from unreachable or non-exploited dependency noise. "
        "Produce concise, board-ready and CSIRT-ready compliance drafts."
    )

    prompt_payload = {
        "regulatory_regime": regime.value,
        "scan_summary": summary.model_dump(),
        "prioritized_findings": compact_findings,
    }

    from google import genai  # Imported lazily so deterministic mode never fails if SDK missing

    client = genai.Client()
    input_json = json.dumps(prompt_payload, indent=2)
    response_format = {
        "type": "text",
        "mime_type": "application/json",
        "schema": EnisaCraDossier.model_json_schema(),
    }

    last_error: Exception | None = None
    for model in model_chain:
        print(f"[ProofCRA]    -> Trying {model} (timeout {per_model_timeout_sec:.0f}s)...", file=sys.stderr)
        result_box: dict[str, Any] = {}

        def _invoke(target_model: str = model, box: dict[str, Any] = result_box) -> None:
            try:
                # Strictly current google-genai Interactions API: NO deprecated temperature/top_p/top_k params
                box["interaction"] = client.interactions.create(
                    model=target_model,
                    system_instruction=system_instruction,
                    input=input_json,
                    response_format=response_format,
                    generation_config={
                        "thinking_level": thinking_level,
                        "max_output_tokens": max_output_tokens,
                    },
                    timeout=per_model_timeout_sec,
                )
            except Exception as exc:
                box["error"] = exc

        worker = threading.Thread(target=_invoke, daemon=True)
        worker.start()
        worker.join(timeout=per_model_timeout_sec + 2.0)

        if worker.is_alive():
            last_error = TimeoutError(f"{model} exceeded {per_model_timeout_sec:.0f}s wall-clock limit")
            print(
                f"[ProofCRA]    -> {model} timed out after {per_model_timeout_sec:.0f}s; failing over...",
                file=sys.stderr,
            )
            continue

        if "error" in result_box:
            last_error = result_box["error"]
            print(
                f"[ProofCRA]    -> {model} failed ({type(last_error).__name__}); failing over...",
                file=sys.stderr,
            )
            continue

        try:
            interaction = result_box["interaction"]
            dossier = EnisaCraDossier.model_validate_json(interaction.output_text)
            # Always enforce mandatory legal-review disclaimer (never allow LLM to dilute it)
            dossier.disclaimer = EnisaCraDossier.model_fields["disclaimer"].default
            usage_obj = getattr(interaction, "usage", None)
            token_usage = LlmTokenUsage(
                input_tokens=getattr(usage_obj, "total_input_tokens", None) if usage_obj else None,
                output_tokens=getattr(usage_obj, "total_output_tokens", None) if usage_obj else None,
                total_tokens=getattr(usage_obj, "total_tokens", None) if usage_obj else None,
            )
            return dossier, model, token_usage
        except Exception as exc:
            last_error = exc
            print(
                f"[ProofCRA]    -> {model} returned invalid schema ({type(exc).__name__}); failing over...",
                file=sys.stderr,
            )

    raise RuntimeError(f"All configured Gemini models failed ({model_chain}): {last_error}")


def scan_repository(
    target: Path,
    output_dir: Path,
    regime: RegulatoryRegime = RegulatoryRegime.CRA,
    skip_llm: bool = False,
    offline_feeds: bool = False,
) -> CraReport:
    if not target.exists():
        raise FileNotFoundError(f"Target path does not exist: {target}")

    output_dir.mkdir(parents=True, exist_ok=True)
    sbom_path = output_dir / "sbom.cdx.json"
    report_path = output_dir / "cra_report.json"

    tool_versions = _detect_tool_versions()
    print(f"[ProofCRA] 1/5 Generating CycloneDX SBOM via Syft for {target}...", file=sys.stderr)
    total_components = _generate_sbom(target, sbom_path)

    print("[ProofCRA] 2/5 Extracting dependency vulnerabilities via OSV-Scanner v2...", file=sys.stderr)
    raw_results = _run_osv_scan(target, sbom_path)

    # Deduplicate & merge alias records (e.g. PYSEC-* and GHSA-* pointing to the same CVE)
    # per (ecosystem, package_name, package_version, canonical_cve_or_osv_id).
    dedup_records: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for res in raw_results:
        for pkg_entry in res.get("packages", []) or []:
            pkg_info = pkg_entry.get("package", {}) or {}
            pkg_name = str(pkg_info.get("name", "")).strip()
            pkg_version = str(pkg_info.get("version", "")).strip()
            ecosystem = str(pkg_info.get("ecosystem", "unknown")).strip()
            purl = pkg_info.get("purl")

            group_sev_map: dict[str, str] = {}
            for grp in pkg_entry.get("groups", []) or []:
                max_sev = grp.get("max_severity")
                for vid in grp.get("ids", []) or []:
                    if max_sev:
                        group_sev_map[str(vid)] = str(max_sev)

            for vuln in pkg_entry.get("vulnerabilities", []) or []:
                osv_id = str(vuln.get("id", "")).strip()
                if not pkg_name or not osv_id:
                    continue

                aliases = [str(a) for a in (vuln.get("aliases", []) or [])]
                cve_ids = _collect_cve_ids(osv_id, aliases)
                canonical_id = sorted(cve_ids)[0] if cve_ids else osv_id
                key = (ecosystem.lower(), pkg_name.lower(), pkg_version, canonical_id)

                severity, cvss_score = _extract_severity_and_score(vuln, group_sev_map.get(osv_id))
                fixed_versions = _extract_fixed_versions(vuln, pkg_name)
                refs = list(
                    dict.fromkeys(
                        str(r.get("url"))
                        for r in (vuln.get("references", []) or [])
                        if isinstance(r, dict) and r.get("url")
                    )
                )
                summary_text = str(vuln.get("summary") or vuln.get("details") or "")[:400].strip()

                if key not in dedup_records:
                    dedup_records[key] = {
                        "osv_id": osv_id,
                        "cve_ids": list(cve_ids),
                        "aliases": list(dict.fromkeys([*aliases])),
                        "pkg_name": pkg_name,
                        "pkg_version": pkg_version,
                        "ecosystem": ecosystem,
                        "purl": purl,
                        "severity": severity,
                        "cvss_score": cvss_score,
                        "fixed_versions": list(fixed_versions),
                        "summary": summary_text,
                        "references": refs,
                    }
                else:
                    existing = dedup_records[key]
                    # Prefer GHSA-* over PYSEC-* as canonical display osv_id if available
                    if existing["osv_id"].startswith("PYSEC-") and osv_id.startswith("GHSA-"):
                        if existing["osv_id"] not in existing["aliases"]:
                            existing["aliases"].append(existing["osv_id"])
                        existing["osv_id"] = osv_id
                    elif osv_id != existing["osv_id"] and osv_id not in existing["aliases"]:
                        existing["aliases"].append(osv_id)

                    for cve in cve_ids:
                        if cve not in existing["cve_ids"]:
                            existing["cve_ids"].append(cve)
                    for alias in aliases:
                        if alias != existing["osv_id"] and alias not in existing["aliases"]:
                            existing["aliases"].append(alias)
                    for fv in fixed_versions:
                        if fv not in existing["fixed_versions"]:
                            existing["fixed_versions"].append(fv)
                    for ref in refs:
                        if ref not in existing["references"]:
                            existing["references"].append(ref)
                    if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(existing["severity"], 0):
                        existing["severity"] = severity
                    if cvss_score is not None and (
                        existing["cvss_score"] is None or cvss_score > existing["cvss_score"]
                    ):
                        existing["cvss_score"] = cvss_score
                    if len(summary_text) > len(existing["summary"]):
                        existing["summary"] = summary_text
                    if not existing["purl"] and purl:
                        existing["purl"] = purl

    print(
        f"[ProofCRA] 3/5 Cross-referencing {len(dedup_records)} deduplicated vulnerability(ies) against CISA KEV + ENISA EUVD...",
        file=sys.stderr,
    )
    print("[ProofCRA] 4/5 Running Tier-2 deterministic AST/import reachability analysis...", file=sys.stderr)

    findings: list[VulnerabilityFinding] = []
    reachability_cache: dict[tuple[str, str], Any] = {}

    # Pre-load KEV first so we prioritize KEV/HIGH CVEs for EUVD lookups
    with ThreatIntelClient(offline=offline_feeds) as intel_client:
        kev_index = intel_client.load_cisa_kev()

        def _pre_sort_key(rec: dict[str, Any]) -> tuple[int, float]:
            is_kev = int(any(c in kev_index for c in rec["cve_ids"]))
            score = float(rec["cvss_score"] or 0.0)
            return (-is_kev, -score)

        sorted_records = sorted(dedup_records.values(), key=_pre_sort_key)

        for rec in sorted_records:
            osv_id = rec["osv_id"]
            aliases = rec["aliases"]
            cve_ids = rec["cve_ids"]
            severity = rec["severity"]
            cvss_score = rec["cvss_score"]
            fixed_versions = rec["fixed_versions"]
            refs = rec["references"][:5]

            exploit_intel = intel_client.enrich(cve_ids, query_euvd=True)

            # Use EUVD CVSS score if OSV did not provide numeric CVSS
            if cvss_score is None and exploit_intel.euvd_base_score is not None:
                cvss_score = exploit_intel.euvd_base_score

            reach_key = (rec["ecosystem"].lower(), rec["pkg_name"].lower())
            if reach_key not in reachability_cache:
                reachability_cache[reach_key] = analyze_reachability(
                    target, rec["ecosystem"], rec["pkg_name"]
                )
            reachability = reachability_cache[reach_key]

            cra_triggered = bool(
                exploit_intel.actively_exploited and reachability.is_potentially_reachable
            )
            action = _build_recommended_action(
                package_name=rec["pkg_name"],
                ecosystem=rec["ecosystem"],
                fixed_versions=fixed_versions,
                cra_triggered=cra_triggered,
                actively_exploited=exploit_intel.actively_exploited,
                is_reachable=reachability.is_potentially_reachable,
            )

            findings.append(
                VulnerabilityFinding(
                    osv_id=osv_id,
                    cve_ids=cve_ids,
                    aliases=aliases,
                    package_name=rec["pkg_name"],
                    package_version=rec["pkg_version"],
                    ecosystem=rec["ecosystem"],
                    purl=rec["purl"],
                    severity=severity,
                    cvss_score=cvss_score,
                    fixed_versions=fixed_versions,
                    summary=rec["summary"],
                    references=refs,
                    exploit_intel=exploit_intel,
                    reachability=reachability,
                    cra_article14_triggered=cra_triggered,
                    recommended_action=action,
                )
            )

    findings.sort(
        key=lambda f: (
            not f.cra_article14_triggered,
            not f.exploit_intel.actively_exploited,
            not f.reachability.is_potentially_reachable,
            -(f.cvss_score or 0.0),
            f.package_name.lower(),
        )
    )

    total_vulns = len(findings)
    exploited_count = sum(1 for f in findings if f.exploit_intel.actively_exploited)
    reachable_count = sum(1 for f in findings if f.reachability.is_potentially_reachable)
    exploited_reachable_count = sum(1 for f in findings if f.cra_article14_triggered)
    noise_reduction = (
        round(((total_vulns - exploited_reachable_count) / total_vulns) * 100.0, 1)
        if total_vulns > 0
        else 100.0
    )

    summary = ScanSummary(
        total_sbom_components=total_components,
        total_vulnerabilities=total_vulns,
        actively_exploited_count=exploited_count,
        reachable_vulnerabilities_count=reachable_count,
        actively_exploited_and_reachable_count=exploited_reachable_count,
        cra_24h_clock_triggered=exploited_reachable_count > 0,
        alert_noise_reduction_pct=noise_reduction,
    )

    # Step 5: Token-guarded Gemini 3.8 Flash structured ENISA dossier
    llm_model_used: str | None = None
    llm_token_usage: LlmTokenUsage | None = None

    if total_vulns == 0:
        print("[ProofCRA] 5/5 Zero findings — skipping LLM call (0 tokens spent).", file=sys.stderr)
        dossier = _build_deterministic_dossier(regime, findings, summary)
        llm_status = "skipped_zero_findings"
    elif skip_llm or not os.environ.get("GEMINI_API_KEY", "").strip():
        print(
            "[ProofCRA] 5/5 GEMINI_API_KEY not set (or --skip-llm) — using deterministic ENISA dossier.",
            file=sys.stderr,
        )
        dossier = _build_deterministic_dossier(regime, findings, summary)
        llm_status = "skipped_missing_api_key"
    else:
        print("[ProofCRA] 5/5 Generating structured ENISA compliance dossier via Gemini 3.8 Flash...", file=sys.stderr)
        try:
            dossier, llm_model_used, llm_token_usage = _run_gemini_triage(regime, findings, summary)
            llm_status = "completed"
        except Exception as exc:
            print(f"[ProofCRA] Warning: Gemini triage failed ({exc}); using deterministic dossier.", file=sys.stderr)
            dossier = _build_deterministic_dossier(regime, findings, summary)
            llm_status = f"fallback_error: {type(exc).__name__}"

    report = CraReport(
        generated_at=datetime.now(timezone.utc),
        tool_versions=tool_versions,
        target_path=str(target),
        regime=regime,
        sbom_path=str(sbom_path),
        summary=summary,
        findings=findings,
        enisa_dossier=dossier,
        llm_triage_status=llm_status,
        llm_model_used=llm_model_used,
        llm_token_usage=llm_token_usage,
    )

    report_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    print(f"[ProofCRA] Done! Report written to {report_path}", file=sys.stderr)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="ProofCRA — Deterministic EU CRA/NIS2 Reachability & ENISA Compliance Scanner"
    )
    parser.add_argument(
        "--target",
        type=Path,
        default=Path("/target"),
        help="Path to target repository or lockfile directory (default: /target)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("/output"),
        help="Output directory for sbom.cdx.json and cra_report.json (default: /output)",
    )
    parser.add_argument(
        "--regime",
        type=str,
        choices=["CRA", "NIS2"],
        default=os.environ.get("PROOFCRA_REGIME", "CRA").upper(),
        help="Regulatory regime mode: CRA (default) or NIS2 (pure cloud SaaS)",
    )
    parser.add_argument(
        "--skip-llm",
        action="store_true",
        help="Skip Gemini API call and emit deterministic ENISA dossier only",
    )
    parser.add_argument(
        "--offline-feeds",
        action="store_true",
        help="Do not query remote CISA KEV / ENISA EUVD feeds (use local cache only)",
    )

    args = parser.parse_args()
    report = scan_repository(
        target=args.target,
        output_dir=args.output,
        regime=RegulatoryRegime(args.regime),
        skip_llm=args.skip_llm,
        offline_feeds=args.offline_feeds,
    )

    # Concise stdout summary for CI / CLI readability
    s = report.summary
    print(
        json.dumps(
            {
                "regime": report.regime.value,
                "cra_24h_clock_triggered": s.cra_24h_clock_triggered,
                "reporting_clock_status": report.enisa_dossier.reporting_clock_status,
                "sbom_components": s.total_sbom_components,
                "total_vulnerabilities": s.total_vulnerabilities,
                "actively_exploited": s.actively_exploited_count,
                "actively_exploited_and_reachable": s.actively_exploited_and_reachable_count,
                "alert_noise_reduction_pct": s.alert_noise_reduction_pct,
                "llm_triage_status": report.llm_triage_status,
                "report_file": str(args.output / "cra_report.json"),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
