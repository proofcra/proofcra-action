"""GitHub Actions entrypoint for ProofCRA Marketplace Action.

Executes ProofCRA deterministic SBOM + OSV + CISA KEV + ENISA EUVD + Tier-2 Reachability
(and optional Tier-3 precondition verification), writes structured outputs to $GITHUB_OUTPUT,
and renders a clean, zero-noise compliance summary into $GITHUB_STEP_SUMMARY.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, "/app")

from models import RegulatoryRegime
from sandbox_verify import run_tier3_verification
from scanner import scan_repository


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


def _write_github_output(outputs: dict[str, str]) -> None:
    out_file = os.environ.get("GITHUB_OUTPUT", "").strip()
    if not out_file:
        return
    with Path(out_file).open("a", encoding="utf-8") as fh:
        for key, val in outputs.items():
            fh.write(f"{key}={val}\n")


def render_markdown_summary(
    report: dict,
    tier3: dict | None,
    regime: str,
) -> str:
    s = report["summary"]
    clock_triggered = bool(s["cra_24h_clock_triggered"])
    if tier3 and tier3.get("proofs"):
        # If Tier-3 verified every active CVE as MITIGATED_BY_CONFIG, reflect that clearly!
        clock_confirmed = tier3.get("confirmed_exploitable_count", 0) > 0
    else:
        clock_confirmed = clock_triggered

    badge = (
        "🚨 **24-HOUR ENISA REPORTING CLOCK TRIGGERED**"
        if clock_confirmed
        else (
            "🛡️ **MITIGATED BY CONFIG (TIER-3 VERIFIED)**"
            if (clock_triggered and not clock_confirmed)
            else "✅ **NO 24-HOUR ENISA CLOCK TRIGGERED**"
        )
    )

    lines = [
        f"## ProofCRA — EU {regime} Compliance & Reachability Report",
        "",
        badge,
        "",
        "| Metric | Value |",
        "| :--- | :--- |",
        f"| CycloneDX SBOM Components | `{s['total_sbom_components']}` |",
        f"| Deduplicated Vulnerabilities | `{s['total_vulnerabilities']}` |",
        f"| Actively Exploited (CISA KEV / ENISA EUVD) | `{s['actively_exploited_count']}` |",
        f"| Statically Reachable & Exploited | `{s['actively_exploited_and_reachable_count']}` |",
        f"| Alert Noise Eliminated | **`{s['alert_noise_reduction_pct']}%`** |",
    ]
    if tier3:
        lines.append(
            f"| Tier-3 Confirmed Exploitable / Config-Mitigated | "
            f"`{tier3['confirmed_exploitable_count']}` confirmed / `{tier3['mitigated_by_config_count']}` mitigated |"
        )
        lines.append(f"| Tier-3 SHA-256 Proof Receipt | `{tier3['receipt_sha256'][:16]}...` |")

    priority = [f for f in report.get("findings", []) if f.get("cra_article14_triggered")]
    if priority:
        lines.extend(
            [
                "",
                "### Priority EU CRA Article 14 Findings",
                "",
                "| CVE / EUVD | Package | Reachability Proof | Required Fix |",
                "| :--- | :--- | :--- | :--- |",
            ]
        )
        for f in priority[:10]:
            cve = (f.get("cve_ids") or [f["osv_id"]])[0]
            euvd = (f.get("exploit_intel") or {}).get("euvd_id") or "-"
            reach = f.get("reachability") or {}
            sites = ", ".join((reach.get("call_sites") or reach.get("matched_files") or [])[:2]) or reach.get("status", "-")
            fix = (f.get("fixed_versions") or ["See advisory"])[0]
            lines.append(
                f"| `{cve}` / `{euvd}` | `{f['ecosystem']}/{f['package_name']}@{f['package_version']}` | `{sites}` | `>= {fix}` |"
            )

    steps = (report.get("enisa_dossier") or {}).get("prioritized_remediation_steps") or []
    if steps:
        lines.extend(["", "### Prioritized Remediation Steps", ""])
        for step in steps[:6]:
            lines.append(f"- {step}")

    lines.extend(
        [
            "",
            "---",
            "_Generated deterministically by [ProofCRA](https://proofcra.dev) (Syft + OSV-Scanner v2.7.1 + CISA KEV + ENISA EUVD). "
            "Upload `sbom.cdx.json` and `cra_report.json` as build artifacts for your ENISA SRP audit trail._",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    workspace = Path(os.environ.get("GITHUB_WORKSPACE", "/github/workspace"))
    target_rel = os.environ.get("INPUT_TARGET_PATH", ".").strip() or "."
    output_rel = os.environ.get("INPUT_OUTPUT_DIR", "proofcra-artifacts").strip() or "proofcra-artifacts"
    regime_raw = os.environ.get("INPUT_REGIME", "CRA").strip().upper()
    fail_on_clock = _env_bool("INPUT_FAIL_ON_CRA_CLOCK", True)
    run_tier3 = _env_bool("INPUT_RUN_TIER3_PROOF", True)

    gemini_key = os.environ.get("INPUT_GEMINI_API_KEY", "").strip()
    if gemini_key:
        os.environ["GEMINI_API_KEY"] = gemini_key

    target_path = (workspace / target_rel).resolve()
    output_dir = (workspace / output_rel).resolve()

    if not target_path.exists():
        print(f"::error::ProofCRA target-path does not exist: {target_path}", file=sys.stderr)
        return 2

    regime = RegulatoryRegime(regime_raw if regime_raw in {"CRA", "NIS2"} else "CRA")
    report_obj = scan_repository(
        target=target_path,
        output_dir=output_dir,
        regime=regime,
        skip_llm=not bool(os.environ.get("GEMINI_API_KEY", "").strip()),
    )
    report_dict = json.loads(report_obj.model_dump_json())
    report_file = output_dir / "cra_report.json"
    sbom_file = output_dir / "sbom.cdx.json"

    tier3_dict: dict | None = None
    tier3_path_str = ""
    if run_tier3:
        receipt = run_tier3_verification(target_path, report_file, output_dir)
        tier3_dict = json.loads(receipt.model_dump_json())
        tier3_path_str = str(output_dir / "tier3_proofs.json")

    md = render_markdown_summary(report_dict, tier3_dict, regime.value)
    summary_md_file = output_dir / "summary.md"
    summary_md_file.write_text(md, encoding="utf-8")

    step_summary = os.environ.get("GITHUB_STEP_SUMMARY", "").strip()
    if step_summary:
        with Path(step_summary).open("a", encoding="utf-8") as fh:
            fh.write(md)

    s = report_dict["summary"]
    effective_clock = (
        tier3_dict["confirmed_exploitable_count"] > 0
        if (tier3_dict and tier3_dict.get("proofs"))
        else bool(s["cra_24h_clock_triggered"])
    )

    _write_github_output(
        {
            "cra-clock-triggered": "true" if effective_clock else "false",
            "total-vulnerabilities": str(s["total_vulnerabilities"]),
            "actively-exploited-count": str(s["actively_exploited_count"]),
            "noise-reduction-pct": str(s["alert_noise_reduction_pct"]),
            "sbom-path": str(sbom_file),
            "report-path": str(report_file),
            "tier3-receipt-path": tier3_path_str,
        }
    )

    print(md)

    if fail_on_clock and effective_clock:
        print(
            "::error::ProofCRA detected actively exploited, reachable CVE(s) triggering the 24h EU CRA Article 14 reporting clock.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
