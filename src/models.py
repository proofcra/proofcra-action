"""Pydantic v2 data contracts for ProofCRA deterministic scanning and ENISA dossiers."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class RegulatoryRegime(str, Enum):
    CRA = "CRA"
    NIS2 = "NIS2"


class ReachabilityStatus(str, Enum):
    DIRECT_IMPORT_AND_CALL = "DIRECT_IMPORT_AND_CALL"
    DIRECT_IMPORT = "DIRECT_IMPORT"
    BUILD_OR_RUNTIME_CONFIG = "BUILD_OR_RUNTIME_CONFIG"
    DECLARED_DIRECT_DEPENDENCY = "DECLARED_DIRECT_DEPENDENCY"
    TRANSITIVE_ONLY = "TRANSITIVE_ONLY"
    UNVERIFIED_LOCKFILE_ONLY = "UNVERIFIED_LOCKFILE_ONLY"


class ReachabilityEvidence(BaseModel):
    status: ReachabilityStatus = Field(
        description="Deterministic Tier-2 static reachability classification."
    )
    is_potentially_reachable: bool = Field(
        description="True unless statically confirmed unreachable or unused."
    )
    matched_files: list[str] = Field(
        default_factory=list,
        description="Relative file paths referencing or configuring the vulnerable package.",
    )
    matched_symbols: list[str] = Field(
        default_factory=list,
        description="Imported modules, functions, or script references observed in source code.",
    )
    call_sites: list[str] = Field(
        default_factory=list,
        description="File:line locations where imported symbols are invoked or configured.",
    )
    confidence: str = Field(
        description="Confidence tier: HIGH, MEDIUM, or LOW."
    )
    explanation: str = Field(
        description="Concise deterministic explanation of reachability findings."
    )


class ExploitIntelligence(BaseModel):
    in_cisa_kev: bool = Field(default=False)
    kev_date_added: Optional[str] = Field(default=None)
    kev_due_date: Optional[str] = Field(default=None)
    kev_required_action: Optional[str] = Field(default=None)
    kev_known_ransomware_use: Optional[str] = Field(default=None)
    in_enisa_euvd: bool = Field(default=False)
    euvd_id: Optional[str] = Field(default=None)
    euvd_base_score: Optional[float] = Field(default=None)
    euvd_epss: Optional[float] = Field(default=None)
    euvd_exploited: bool = Field(default=False)
    actively_exploited: bool = Field(
        default=False,
        description="True when flagged as actively exploited in CISA KEV or ENISA EUVD.",
    )


class VulnerabilityFinding(BaseModel):
    osv_id: str
    cve_ids: list[str] = Field(default_factory=list)
    aliases: list[str] = Field(default_factory=list)
    package_name: str
    package_version: str
    ecosystem: str
    purl: Optional[str] = None
    severity: str = Field(default="UNKNOWN")
    cvss_score: Optional[float] = None
    fixed_versions: list[str] = Field(default_factory=list)
    summary: str = Field(default="")
    references: list[str] = Field(default_factory=list)
    exploit_intel: ExploitIntelligence
    reachability: ReachabilityEvidence
    cra_article14_triggered: bool = Field(
        description="True when actively exploited AND potentially reachable in shipped software."
    )
    recommended_action: str


class EnisaCraDossier(BaseModel):
    """Structured ENISA Single Reporting Platform (SRP) compliance dossier schema."""

    regime: str = Field(
        description="Applicable EU regulatory regime: CRA or NIS2."
    )
    reporting_clock_status: str = Field(
        description=(
            "One of: ACTIVE_24H_EARLY_WARNING_REQUIRED, "
            "URGENT_VERIFICATION_REQUIRED, MONITOR_AND_PATCH, or COMPLIANT_NO_ACTIVE_EXPLOITS."
        )
    )
    executive_summary: str = Field(
        description="Concise CISO/CTO summary of legal exposure, active exploitation status, and reachability."
    )
    affected_critical_cves: list[str] = Field(
        default_factory=list,
        description="List of actively exploited or critical CVE/OSV IDs driving compliance obligations.",
    )
    early_warning_24h_draft: str = Field(
        description=(
            "Draft ENISA SRP 24-hour Early Warning (CRA Art. 14(2)(a)): affected product/component, "
            "actively exploited CVE(s), suspected unlawful/malicious exploitation note, and Member States placeholder."
        )
    )
    vulnerability_notification_72h_draft: str = Field(
        description=(
            "Draft ENISA SRP 72-hour Vulnerability Notification (CRA Art. 14(2)(b)): technical severity, "
            "Tier-2 reachability proof summary, compensating controls, and patch timeline."
        )
    )
    final_report_14d_checklist: list[str] = Field(
        default_factory=list,
        description="Actionable checklist for the ENISA SRP 14-day Final Report (CRA Art. 14(2)(c)) once patched.",
    )
    article_14_8_customer_notice_draft: str = Field(
        description=(
            "Draft customer/user security advisory required under CRA Article 14(8) detailing "
            "risk-mitigation measures and upgrade instructions."
        )
    )
    prioritized_remediation_steps: list[str] = Field(
        default_factory=list,
        description="Ordered, copy-pasteable engineering remediation steps (exact package upgrades & lockfile refreshes).",
    )
    disclaimer: str = Field(
        default=(
            "Automated ProofCRA compliance draft generated from deterministic SBOM, OSV, KEV/EUVD, "
            "and static reachability evidence. Must be reviewed by legal counsel / security officer "
            "before formal submission to the ENISA Single Reporting Platform (SRP)."
        )
    )


class ScanSummary(BaseModel):
    total_sbom_components: int
    total_vulnerabilities: int
    actively_exploited_count: int
    reachable_vulnerabilities_count: int
    actively_exploited_and_reachable_count: int
    cra_24h_clock_triggered: bool
    alert_noise_reduction_pct: float = Field(
        description="Percentage of raw dependency vulnerabilities filtered out as non-exploited/non-CRA-clock."
    )


class LlmTokenUsage(BaseModel):
    input_tokens: Optional[int] = None
    output_tokens: Optional[int] = None
    total_tokens: Optional[int] = None


class CraReport(BaseModel):
    schema_version: str = Field(default="1.0.0")
    generated_at: datetime
    tool_versions: dict[str, str] = Field(default_factory=dict)
    target_path: str
    regime: RegulatoryRegime
    sbom_path: str
    summary: ScanSummary
    findings: list[VulnerabilityFinding] = Field(default_factory=list)
    enisa_dossier: EnisaCraDossier
    llm_triage_status: str = Field(
        description=(
            "One of: completed, skipped_zero_findings, skipped_missing_api_key, or fallback_error."
        )
    )
    llm_model_used: Optional[str] = None
    llm_token_usage: Optional[LlmTokenUsage] = None
