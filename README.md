# ProofCRA — EU CRA & NIS2 Reachability Scanner (GitHub Action)

[![EU CRA Article 14](https://img.shields.io/badge/EU%20CRA-Art.%2014%20Live-4f7cff)](https://proofcra.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-10b981.svg)](LICENSE)

Free, deterministic **EU Cyber Resilience Act (Regulation 2024/2847)** and **NIS2** reachability gate for **Node.js** and **Python** repositories.

Under **EU CRA Article 14** (enforceable since **September 11, 2026**), manufacturers of products with digital elements must submit an **Early Warning to the ENISA Single Reporting Platform (SRP) within 24 hours** of becoming aware of an actively exploited vulnerability. Traditional SCA scanners flood teams with hundreds of non-exploited, unreachable alerts. **ProofCRA eliminates 90%+ of alert fatigue deterministically.**

## What This Action Does

1. **CycloneDX SBOM Generation:** Runs **Anchore Syft** to emit an audit-ready `sbom.cdx.json`.
2. **Dependency Vulnerability Extraction:** Runs **Google OSV-Scanner v2.7.1** and deduplicates `PYSEC` / `GHSA` / `CVE` aliases.
3. **Live European Active-Exploit Filtering:** Cross-references live **CISA KEV** + **ENISA EUVD** (European Vulnerability Database) feeds to isolate CVEs that actually trigger the 24-hour reporting clock.
4. **Tier-2 AST/Import Reachability:** Deterministically traces Python AST and JS/TS imports/call sites + config/script bindings with zero secrets and zero LLM tokens.
5. **Tier-3 Precondition & Config-Mitigation Proof:** Verifies exploitability preconditions (e.g., `TrustedHostMiddleware` on Starlette, `--host` exposure on Vite), outputs a tamper-evident **SHA-256 Proof Receipt**, and generates a minimal unified fix diff (`recommended_patch.diff`).
6. **ENISA SRP Compliance Dossier:** Generates structured 24h Early Warning, 72h Notification, 14d Final Report Checklist, and Article 14(8) Customer Notice drafts (`cra_report.json`) plus a clean GitHub Step Summary.

## Quickstart

Create `.github/workflows/proofcra.yml`:

```yaml
name: ProofCRA EU Compliance Gate

on:
  pull_request:
  push:
    branches: [main]

jobs:
  proofcra:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run ProofCRA Reachability & CRA Clock Scan
        id: proofcra
        uses: proofcra/proofcra-action@v1
        with:
          target-path: "."
          regime: "CRA"            # Use "NIS2" for pure browser-only SaaS
          fail-on-cra-clock: "true"
          run-tier3-proof: "true"

      - name: Upload CycloneDX SBOM & ENISA Dossier Bundle
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: proofcra-enisa-bundle
          path: proofcra-artifacts/
```

## Inputs

| Input | Default | Description |
| :--- | :--- | :--- |
| `target-path` | `.` | Relative directory inside the repository to scan |
| `regime` | `CRA` | Regulatory regime: `CRA` (shipped/hybrid/self-hosted/CLI/IoT) or `NIS2` (pure cloud SaaS) |
| `fail-on-cra-clock` | `true` | Exit with code `1` if an actively exploited, unmitigated reachable CVE triggers the 24h ENISA clock |
| `run-tier3-proof` | `true` | Run deterministic Tier-3 config-mitigation checks & generate `recommended_patch.diff` |
| `output-dir` | `proofcra-artifacts` | Output directory for `sbom.cdx.json`, `cra_report.json`, `tier3_proofs.json`, and `summary.md` |
| `gemini-api-key` | `""` | Optional Gemini API key (`gemini-3.8-flash` / `gemini-3.5-flash-lite`) for enhanced ENISA dossier prose. Leave blank for 100% deterministic mode |

## Outputs

| Output | Description |
| :--- | :--- |
| `cra-clock-triggered` | `'true'` or `'false'` |
| `total-vulnerabilities` | Deduplicated vulnerability count |
| `actively-exploited-count` | Count of live CISA KEV / ENISA EUVD matches |
| `noise-reduction-pct` | Percentage of non-CRA-clock alert noise filtered |
| `sbom-path` | Path to generated `sbom.cdx.json` |
| `report-path` | Path to generated `cra_report.json` |
| `tier3-receipt-path` | Path to SHA-256 `tier3_proofs.json` receipt |

---

Try the zero-signup web scanner and live EU CRA CVE directory at **[proofcra.dev](https://proofcra.dev)**.
