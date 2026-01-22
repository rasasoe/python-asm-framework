from __future__ import annotations

from typing import Any, Dict, List, Optional
import time
import requests

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def _headers(api_key: Optional[str]) -> Dict[str, str]:
    h = {"Accept": "application/json"}
    if api_key:
        h["apiKey"] = api_key
    return h

def fetch_cve_from_nvd(cve_id: str, api_key: Optional[str] = None, timeout: int = 12) -> Dict[str, Any]:
    """
    NVD CVE API 2.0 기반.
    """
    params = {"cveId": cve_id}
    r = requests.get(NVD_BASE, headers=_headers(api_key), params=params, timeout=timeout)
    r.raise_for_status()
    return r.json()

def enrich_cves_with_nvd(cves: List[Dict[str, Any]], api_key: Optional[str] = None) -> List[Dict[str, Any]]:
    enriched = []
    for c in cves:
        cve_id = c.get("cve")
        if not cve_id:
            continue
        try:
            data = fetch_cve_from_nvd(cve_id, api_key=api_key)
            enriched.append({"cve": cve_id, "nvd": data})
            time.sleep(0.6)  # 과도한 호출 방지(ASM 친화)
        except Exception as e:
            enriched.append({"cve": cve_id, "error": str(e)})
    return enriched
