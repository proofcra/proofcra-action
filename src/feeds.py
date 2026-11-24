"""Live threat-intelligence enrichment: CISA KEV + ENISA EUVD with local disk caching."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import httpx

from models import ExploitIntelligence

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
ENISA_EUVD_LOOKUP_URL = "https://euvdservices.enisa.europa.eu/api/enisaid"

KEV_TTL_SECONDS = 6 * 3600
EUVD_TTL_SECONDS = 12 * 3600
MAX_EUVD_LOOKUPS_PER_SCAN = 25


class ThreatIntelClient:
    """Fetches and caches CISA KEV and ENISA EUVD vulnerability intelligence."""

    def __init__(self, cache_dir: Path | None = None, offline: bool = False) -> None:
        default_dir = Path(os.environ.get("PROOFCRA_CACHE_DIR", "/tmp/proofcra-cache"))
        self.cache_dir = cache_dir or default_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.offline = offline
        self._kev_index: dict[str, dict[str, Any]] | None = None
        self._euvd_cache: dict[str, dict[str, Any]] | None = None
        self._euvd_queries_this_run = 0
        self._http = httpx.Client(
            timeout=12.0,
            follow_redirects=True,
            headers={"User-Agent": "ProofCRA/1.0 (+https://proofcra.dev)"},
        )

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> ThreatIntelClient:
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def _kev_cache_path(self) -> Path:
        return self.cache_dir / "cisa_kev.json"

    def _euvd_cache_path(self) -> Path:
        return self.cache_dir / "enisa_euvd_cache.json"

    def load_cisa_kev(self) -> dict[str, dict[str, Any]]:
        """Load CISA KEV catalog indexed by CVE ID."""
        if self._kev_index is not None:
            return self._kev_index

        cache_file = self._kev_cache_path()
        raw_payload: dict[str, Any] | None = None

        if cache_file.exists():
            age = time.time() - cache_file.stat().st_mtime
            if age < KEV_TTL_SECONDS or self.offline:
                try:
                    raw_payload = json.loads(cache_file.read_text(encoding="utf-8"))
                except Exception as exc:
                    print(f"[ProofCRA] Warning: failed to read KEV cache: {exc}", file=sys.stderr)

        if raw_payload is None and not self.offline:
            try:
                resp = self._http.get(CISA_KEV_URL)
                resp.raise_for_status()
                raw_payload = resp.json()
                cache_file.write_text(json.dumps(raw_payload), encoding="utf-8")
            except Exception as exc:
                print(f"[ProofCRA] Warning: failed to fetch live CISA KEV feed: {exc}", file=sys.stderr)
                if cache_file.exists():
                    try:
                        raw_payload = json.loads(cache_file.read_text(encoding="utf-8"))
                    except Exception:
                        raw_payload = None

        index: dict[str, dict[str, Any]] = {}
        if raw_payload and isinstance(raw_payload.get("vulnerabilities"), list):
            for entry in raw_payload["vulnerabilities"]:
                cve_id = str(entry.get("cveID", "")).strip().upper()
                if cve_id:
                    index[cve_id] = entry

        self._kev_index = index
        return index

    def _load_euvd_cache(self) -> dict[str, dict[str, Any]]:
        if self._euvd_cache is not None:
            return self._euvd_cache

        cache_file = self._euvd_cache_path()
        if cache_file.exists():
            try:
                self._euvd_cache = json.loads(cache_file.read_text(encoding="utf-8"))
                return self._euvd_cache
            except Exception:
                pass
        self._euvd_cache = {}
        return self._euvd_cache

    def _save_euvd_cache(self) -> None:
        if self._euvd_cache is None:
            return
        try:
            self._euvd_cache_path().write_text(
                json.dumps(self._euvd_cache), encoding="utf-8"
            )
        except Exception:
            pass

    def lookup_enisa_euvd(self, cve_id: str) -> dict[str, Any] | None:
        """Query ENISA European Vulnerability Database (EUVD) by CVE ID."""
        cve_upper = cve_id.strip().upper()
        if not cve_upper.startswith("CVE-"):
            return None

        cache = self._load_euvd_cache()
        cached = cache.get(cve_upper)
        now = time.time()
        if cached is not None:
            if (now - cached.get("_fetched_at", 0) < EUVD_TTL_SECONDS) or self.offline:
                return cached.get("data")

        if self.offline or self._euvd_queries_this_run >= MAX_EUVD_LOOKUPS_PER_SCAN:
            return cached.get("data") if cached else None

        self._euvd_queries_this_run += 1
        try:
            resp = self._http.get(ENISA_EUVD_LOOKUP_URL, params={"id": cve_upper})
            if resp.status_code == 200:
                payload = resp.json()
                if isinstance(payload, dict) and payload.get("id"):
                    cache[cve_upper] = {"_fetched_at": now, "data": payload}
                    self._save_euvd_cache()
                    return payload
            cache[cve_upper] = {"_fetched_at": now, "data": None}
            self._save_euvd_cache()
        except Exception as exc:
            print(
                f"[ProofCRA] Warning: ENISA EUVD lookup failed for {cve_upper}: {exc}",
                file=sys.stderr,
            )
        return None

    def enrich(self, cve_ids: list[str], query_euvd: bool = True) -> ExploitIntelligence:
        """Cross-reference CVE IDs against CISA KEV and ENISA EUVD."""
        kev_index = self.load_cisa_kev()
        intel = ExploitIntelligence()

        for raw_cve in cve_ids:
            cve = raw_cve.strip().upper()
            if cve in kev_index:
                entry = kev_index[cve]
                intel.in_cisa_kev = True
                intel.kev_date_added = entry.get("dateAdded")
                intel.kev_due_date = entry.get("dueDate")
                intel.kev_required_action = entry.get("requiredAction")
                intel.kev_known_ransomware_use = entry.get("knownRansomwareCampaignUse")
                break

        if query_euvd:
            for raw_cve in cve_ids:
                euvd = self.lookup_enisa_euvd(raw_cve)
                if euvd:
                    intel.in_enisa_euvd = True
                    intel.euvd_id = str(euvd.get("id")) if euvd.get("id") else None
                    base_score = euvd.get("baseScore")
                    if isinstance(base_score, (int, float)):
                        intel.euvd_base_score = float(base_score)
                    epss = euvd.get("epss")
                    if isinstance(epss, (int, float)):
                        intel.euvd_epss = float(epss)
                    exploited_since = euvd.get("exploitedSince")
                    if exploited_since:
                        intel.euvd_exploited = True
                    break

        intel.actively_exploited = bool(intel.in_cisa_kev or intel.euvd_exploited)
        return intel
