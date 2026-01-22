from __future__ import annotations

from typing import Any, Dict, List, Optional
from vulners import VulnersApi

def _build_query(product: str, version: str, extrainfo: str = "") -> Optional[str]:
    product = (product or "").strip()
    version = (version or "").strip()
    extrainfo = (extrainfo or "").strip()

    if not product and not version:
        return None
    if product and version:
        q = f"{product} {version}"
        if extrainfo and len(extrainfo) <= 40:
            q += f" {extrainfo}"
        return q
    # product만 있는 경우: 노이즈가 커서 기본은 None
    return None

def map_services_with_vulners(api_key: str, ports: List[dict], per_service_limit: int = 8) -> List[dict]:
    if not api_key:
        # 키 없으면 그대로 반환
        return ports

    api = VulnersApi(api_key=api_key)

    for p in ports:
        q = _build_query(p.get("product",""), p.get("version",""), p.get("extrainfo",""))
        p["vulners_query"] = q
        if not q:
            continue

        try:
            res = api.search(q, limit=per_service_limit)
        except Exception as e:
            p.setdefault("errors", []).append(f"VULNERS_ERROR: {e}")
            continue

        matches = []
        for r in res:
            vid = r.get("id") or r.get("_id") or ""
            if not str(vid).startswith("CVE-"):
                continue
            matches.append({
                "cve": str(vid),
                "title": r.get("title") or "",
                "cvss": (r.get("cvss") or {}).get("score") if isinstance(r.get("cvss"), dict) else r.get("cvssScore"),
                "href": r.get("href") or "",
            })

        p["cve_matches"] = matches

    return ports
