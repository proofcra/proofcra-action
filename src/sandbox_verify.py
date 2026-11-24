"""ProofCRA Tier-3 Isolated Sandbox Precondition Verifier & Patch Diff Generator.

Designed to execute inside a network-isolated (`--network=none`), read-only, unprivileged
container (`uid=10001`, `--cap-drop=ALL`, `--security-opt=no-new-privileges:true`) against
a read-only mounted target repository and a Phase-1/2 `cra_report.json`.

Produces:
  1. Deterministic precondition proofs distinguishing `CONFIRMED_EXPLOITABLE_PRECONDITIONS`
     from `MITIGATED_BY_CONFIG` (eliminating config-mitigated false alarms).
  2. Minimal, audit-ready dependency upgrade unified patch previews (`recommended_patch.diff`).
  3. Cryptographic SHA-256 receipt (`tier3_proofs.json`) suitable for ENISA SRP attachments.
"""

from __future__ import annotations

import argparse
import ast
import difflib
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".next"}


class Tier3ProofItem(BaseModel):
    cve_id: str
    osv_id: str
    package: str
    verdict: str = Field(
        description=(
            "CONFIRMED_EXPLOITABLE_PRECONDITIONS, MITIGATED_BY_CONFIG, "
            "UNREACHABLE_CONFIRMED, or MANUAL_RUNTIME_REVIEW_NEEDED"
        )
    )
    enisa_24h_clock_confirmed: bool
    checks_executed: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    mitigation_detected: list[str] = Field(default_factory=list)
    fixed_version: str | None = None
    suggested_patch_file: str | None = None


class Tier3Receipt(BaseModel):
    schema_version: str = "1.0.0"
    generated_at: datetime
    isolation_mode: str = "network_none_unprivileged_sandbox"
    target_path: str
    report_sha256: str
    proofs: list[Tier3ProofItem] = Field(default_factory=list)
    confirmed_exploitable_count: int = 0
    mitigated_by_config_count: int = 0
    patch_diff_path: str | None = None
    receipt_sha256: str = ""


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _iter_files(root: Path, extensions: set[str]) -> list[Path]:
    out: list[Path] = []
    if not root.is_dir():
        return out
    for p in root.rglob("*"):
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.is_file() and p.suffix.lower() in extensions:
            out.append(p)
    return sorted(out)


def _verify_vite_fs_deny_bypass(target: Path, finding: dict[str, Any]) -> Tier3ProofItem:
    """Verify CVE-2025-31125 / Vite dev server network exposure preconditions.

    Per ENISA EUVD-2025-8866 & GHSA-4r4m-qw57-chr8, apps are exploitable remotely only when
    the Vite dev server is explicitly exposed to the network (`--host` CLI flag or `server.host`).
    """
    cve_id = (finding.get("cve_ids") or [finding["osv_id"]])[0]
    pkg_label = f"{finding['ecosystem']}/{finding['package_name']}@{finding['package_version']}"
    fixed_ver = (finding.get("fixed_versions") or [None])[0]

    checks = [
        "Inspect package.json scripts for Vite '--host' network exposure",
        "Inspect vite.config.{js,mjs,cjs,ts} for server.host non-localhost binding",
    ]
    evidence: list[str] = []
    mitigations: list[str] = []
    exposed = False

    # 1. Check package.json scripts
    for pkg_json in target.rglob("package.json"):
        if any(part in SKIP_DIRS for part in pkg_json.parts):
            continue
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            continue
        rel = str(pkg_json.relative_to(target)).replace("\\", "/")
        scripts = data.get("scripts") or {}
        for name, cmd in scripts.items():
            if not isinstance(cmd, str) or "vite" not in cmd:
                continue
            if re.search(r"--host(?:\s+(?!127\.0\.0\.1|localhost)\S+)?", cmd):
                exposed = True
                evidence.append(f"{rel}:scripts.{name} exposes Vite over network -> '{cmd}'")
            else:
                mitigations.append(f"{rel}:scripts.{name} runs Vite without '--host' ('{cmd}')")

    # 2. Check vite.config.*
    for cfg in target.rglob("vite.config.*"):
        if any(part in SKIP_DIRS for part in cfg.parts):
            continue
        rel = str(cfg.relative_to(target)).replace("\\", "/")
        text = cfg.read_text(encoding="utf-8", errors="ignore")
        host_match = re.search(
            r"host\s*:\s*(true|['\"](0\.0\.0\.0|::|[^'\"]+)['\"])", text
        )
        if host_match:
            val = host_match.group(1).strip("'\"")
            if val in {"localhost", "127.0.0.1", "::1"}:
                mitigations.append(f"{rel} binds server.host strictly to loopback ({val})")
            else:
                exposed = True
                evidence.append(f"{rel} configures network-accessible server.host = {val}")
        else:
            mitigations.append(f"{rel} does not bind server.host to external interfaces")

    if exposed:
        return Tier3ProofItem(
            cve_id=cve_id,
            osv_id=finding["osv_id"],
            package=pkg_label,
            verdict="CONFIRMED_EXPLOITABLE_PRECONDITIONS",
            enisa_24h_clock_confirmed=True,
            checks_executed=checks,
            evidence=evidence,
            mitigation_detected=mitigations,
            fixed_version=fixed_ver,
            suggested_patch_file="package.json",
        )

    return Tier3ProofItem(
        cve_id=cve_id,
        osv_id=finding["osv_id"],
        package=pkg_label,
        verdict="MITIGATED_BY_CONFIG",
        enisa_24h_clock_confirmed=False,
        checks_executed=checks,
        evidence=evidence,
        mitigation_detected=mitigations
        or ["Vite dev server is not configured for external network exposure (--host / server.host)."],
        fixed_version=fixed_ver,
        suggested_patch_file="package.json",
    )


def _verify_starlette_badhost(target: Path, finding: dict[str, Any]) -> Tier3ProofItem:
    """Verify CVE-2026-48710 (Starlette BadHost) middleware mitigation via Python AST inspection.

    Exploitable when Starlette/FastAPI instantiates an ASGI app without TrustedHostMiddleware
    enforcing allowed_hosts (non-wildcard).
    """
    cve_id = (finding.get("cve_ids") or [finding["osv_id"]])[0]
    pkg_label = f"{finding['ecosystem']}/{finding['package_name']}@{finding['package_version']}"
    fixed_ver = (finding.get("fixed_versions") or [None])[0]

    checks = [
        "Parse Python AST for Starlette / FastAPI ASGI application instantiation",
        "Verify presence of TrustedHostMiddleware with non-wildcard allowed_hosts",
    ]
    evidence: list[str] = []
    mitigations: list[str] = []
    has_asgi_app = False
    has_trusted_host = False
    wildcard_hosts = False

    for py_file in _iter_files(target, {".py"}):
        rel = str(py_file.relative_to(target)).replace("\\", "/")
        source = py_file.read_text(encoding="utf-8", errors="ignore")
        try:
            tree = ast.parse(source, filename=rel)
        except SyntaxError:
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr

                if func_name in {"Starlette", "FastAPI"}:
                    has_asgi_app = True
                    evidence.append(f"{rel}:{node.lineno} instantiates {func_name}() ASGI application")

                if func_name == "TrustedHostMiddleware":
                    has_trusted_host = True
                    # Check allowed_hosts for wildcard "*"
                    for kw in node.keywords:
                        if kw.arg == "allowed_hosts" and isinstance(kw.value, (ast.List, ast.Tuple)):
                            vals = [
                                elt.value
                                for elt in kw.value.elts
                                if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
                            ]
                            if "*" in vals:
                                wildcard_hosts = True
                                evidence.append(
                                    f"{rel}:{node.lineno} TrustedHostMiddleware uses wildcard allowed_hosts=['*'] (ineffective)"
                                )
                            else:
                                mitigations.append(
                                    f"{rel}:{node.lineno} enforces TrustedHostMiddleware(allowed_hosts={vals})"
                                )
                elif func_name in {"add_middleware", "Middleware"}:
                    # Handle app.add_middleware(TrustedHostMiddleware, allowed_hosts=[...])
                    arg_names = [
                        a.id for a in node.args if isinstance(a, ast.Name)
                    ] + [
                        a.attr for a in node.args if isinstance(a, ast.Attribute)
                    ]
                    if "TrustedHostMiddleware" in arg_names:
                        has_trusted_host = True
                        for kw in node.keywords:
                            if kw.arg == "allowed_hosts" and isinstance(kw.value, (ast.List, ast.Tuple)):
                                vals = [
                                    elt.value
                                    for elt in kw.value.elts
                                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
                                ]
                                if "*" in vals:
                                    wildcard_hosts = True
                                    evidence.append(
                                        f"{rel}:{node.lineno} add_middleware(TrustedHostMiddleware) uses wildcard '*'"
                                    )
                                else:
                                    mitigations.append(
                                        f"{rel}:{node.lineno} registers TrustedHostMiddleware with strict allowed_hosts={vals}"
                                    )

    if has_asgi_app and (not has_trusted_host or wildcard_hosts):
        if not has_trusted_host:
            evidence.append("No TrustedHostMiddleware detected guarding incoming Host headers.")
        return Tier3ProofItem(
            cve_id=cve_id,
            osv_id=finding["osv_id"],
            package=pkg_label,
            verdict="CONFIRMED_EXPLOITABLE_PRECONDITIONS",
            enisa_24h_clock_confirmed=True,
            checks_executed=checks,
            evidence=evidence,
            mitigation_detected=mitigations,
            fixed_version=fixed_ver,
            suggested_patch_file="requirements.txt",
        )

    if has_asgi_app and has_trusted_host and not wildcard_hosts:
        return Tier3ProofItem(
            cve_id=cve_id,
            osv_id=finding["osv_id"],
            package=pkg_label,
            verdict="MITIGATED_BY_CONFIG",
            enisa_24h_clock_confirmed=False,
            checks_executed=checks,
            evidence=evidence,
            mitigation_detected=mitigations,
            fixed_version=fixed_ver,
            suggested_patch_file="requirements.txt",
        )

    return Tier3ProofItem(
        cve_id=cve_id,
        osv_id=finding["osv_id"],
        package=pkg_label,
        verdict="UNREACHABLE_CONFIRMED",
        enisa_24h_clock_confirmed=False,
        checks_executed=checks,
        evidence=["No Starlette/FastAPI ASGI app instantiation found in scanned Python AST."],
        fixed_version=fixed_ver,
        suggested_patch_file="requirements.txt",
    )


def _verify_generic_finding(finding: dict[str, Any]) -> Tier3ProofItem:
    cve_id = (finding.get("cve_ids") or [finding["osv_id"]])[0]
    pkg_label = f"{finding['ecosystem']}/{finding['package_name']}@{finding['package_version']}"
    fixed_ver = (finding.get("fixed_versions") or [None])[0]
    reach = finding.get("reachability") or {}

    if not reach.get("is_potentially_reachable", True):
        return Tier3ProofItem(
            cve_id=cve_id,
            osv_id=finding["osv_id"],
            package=pkg_label,
            verdict="UNREACHABLE_CONFIRMED",
            enisa_24h_clock_confirmed=False,
            checks_executed=["Cross-check Tier-2 static AST/import reachability"],
            evidence=[reach.get("explanation", "Statically unreachable")],
            fixed_version=fixed_ver,
        )

    return Tier3ProofItem(
        cve_id=cve_id,
        osv_id=finding["osv_id"],
        package=pkg_label,
        verdict="CONFIRMED_EXPLOITABLE_PRECONDITIONS",
        enisa_24h_clock_confirmed=bool(finding.get("cra_article14_triggered")),
        checks_executed=["Verify active CISA KEV / ENISA EUVD signal + Tier-2 direct call-site proof"],
        evidence=(reach.get("call_sites") or reach.get("matched_files") or [reach.get("explanation", "")]),
        fixed_version=fixed_ver,
    )


def _generate_minimal_patch_diff(target: Path, findings: list[dict[str, Any]]) -> str:
    """Generate a clean unified diff patching confirmed actively exploited packages."""
    diffs: list[str] = []

    # Group upgrades by ecosystem
    py_upgrades: dict[str, str] = {}
    npm_upgrades: dict[str, str] = {}
    for f in findings:
        fixed = (f.get("fixed_versions") or [None])[0]
        if not fixed:
            continue
        eco = str(f.get("ecosystem", "")).lower()
        name = str(f.get("package_name", ""))
        if eco == "pypi":
            py_upgrades[name.lower()] = str(fixed)
        elif eco == "npm":
            npm_upgrades[name] = str(fixed)

    # Patch requirements.txt if present
    req_file = target / "requirements.txt"
    if req_file.exists() and py_upgrades:
        orig_lines = req_file.read_text(encoding="utf-8", errors="ignore").splitlines(keepends=True)
        new_lines: list[str] = []
        changed = False
        for line in orig_lines:
            m = re.match(r"^(\s*)([A-Za-z0-9._-]+)(\s*==\s*)([^\s#]+)(.*)$", line)
            if m and m.group(2).lower() in py_upgrades:
                target_ver = py_upgrades[m.group(2).lower()]
                newline = f"{m.group(1)}{m.group(2)}=={target_ver}{m.group(5)}\n"
                if newline != line:
                    changed = True
                new_lines.append(newline)
            else:
                new_lines.append(line)
        if changed:
            diffs.extend(
                difflib.unified_diff(
                    orig_lines, new_lines, fromfile="a/requirements.txt", tofile="b/requirements.txt"
                )
            )

    # Patch package.json if present
    pkg_file = target / "package.json"
    if pkg_file.exists() and npm_upgrades:
        orig_text = pkg_file.read_text(encoding="utf-8", errors="ignore")
        try:
            data = json.loads(orig_text)
            changed = False
            for sec in ("dependencies", "devDependencies"):
                deps = data.get(sec)
                if isinstance(deps, dict):
                    for pkg_name, fixed_ver in npm_upgrades.items():
                        if pkg_name in deps and deps[pkg_name] != fixed_ver:
                            deps[pkg_name] = fixed_ver
                            changed = True
            if changed:
                new_text = json.dumps(data, indent=2) + "\n"
                diffs.extend(
                    difflib.unified_diff(
                        orig_text.splitlines(keepends=True),
                        new_text.splitlines(keepends=True),
                        fromfile="a/package.json",
                        tofile="b/package.json",
                    )
                )
        except Exception:
            pass

    return "".join(diffs)


def run_tier3_verification(target: Path, report_path: Path, output_dir: Path) -> Tier3Receipt:
    report_bytes = report_path.read_bytes()
    report_data = json.loads(report_bytes.decode("utf-8"))
    report_sha = _sha256_bytes(report_bytes)

    findings = report_data.get("findings") or []
    # Focus Tier-3 deep sandbox checks on actively exploited findings (highest ROI & speed)
    priority_findings = [
        f for f in findings if (f.get("exploit_intel") or {}).get("actively_exploited")
    ]

    proofs: list[Tier3ProofItem] = []
    for f in priority_findings:
        cves = {c.upper() for c in (f.get("cve_ids") or [])}
        pkg = str(f.get("package_name", "")).lower()
        if "CVE-2025-31125" in cves or pkg == "vite":
            proofs.append(_verify_vite_fs_deny_bypass(target, f))
        elif "CVE-2026-48710" in cves or pkg == "starlette":
            proofs.append(_verify_starlette_badhost(target, f))
        else:
            proofs.append(_verify_generic_finding(f))

    output_dir.mkdir(parents=True, exist_ok=True)
    patch_diff = _generate_minimal_patch_diff(target, priority_findings)
    patch_path: Path | None = None
    if patch_diff.strip():
        patch_path = output_dir / "recommended_patch.diff"
        patch_path.write_text(patch_diff, encoding="utf-8")

    confirmed = sum(1 for p in proofs if p.verdict == "CONFIRMED_EXPLOITABLE_PRECONDITIONS")
    mitigated = sum(1 for p in proofs if p.verdict == "MITIGATED_BY_CONFIG")

    receipt = Tier3Receipt(
        generated_at=datetime.now(timezone.utc),
        target_path=str(target),
        report_sha256=report_sha,
        proofs=proofs,
        confirmed_exploitable_count=confirmed,
        mitigated_by_config_count=mitigated,
        patch_diff_path=str(patch_path) if patch_path else None,
    )
    # Compute tamper-evident SHA-256 over canonical receipt payload
    canonical = receipt.model_dump_json(exclude={"receipt_sha256"}).encode("utf-8")
    receipt.receipt_sha256 = _sha256_bytes(canonical)

    out_file = output_dir / "tier3_proofs.json"
    out_file.write_text(receipt.model_dump_json(indent=2), encoding="utf-8")
    print(f"[ProofCRA Tier-3] Verified {len(proofs)} active CVE(s) -> {out_file}", file=sys.stderr)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(
        description="ProofCRA Tier-3 Network-Isolated Precondition Verifier & Patch Generator"
    )
    parser.add_argument("--target", type=Path, default=Path("/target"))
    parser.add_argument("--report", type=Path, default=Path("/output/cra_report.json"))
    parser.add_argument("--output", type=Path, default=Path("/output"))
    args = parser.parse_args()

    receipt = run_tier3_verification(args.target, args.report, args.output)
    print(
        json.dumps(
            {
                "confirmed_exploitable_count": receipt.confirmed_exploitable_count,
                "mitigated_by_config_count": receipt.mitigated_by_config_count,
                "patch_diff_path": receipt.patch_diff_path,
                "receipt_sha256": receipt.receipt_sha256,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
