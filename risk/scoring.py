from __future__ import annotations

from typing import Any, Dict, List

NON_STANDARD_WEB_PORTS = {3000, 8000, 8080, 8888, 5000, 7001, 9000}
SENSITIVE_KEYWORDS = ["admin", "manage", "console", "upload", "reset", "password", "token", "debug", "internal"]

def clamp(n: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, n))

def has_kw(s: str) -> bool:
    t = (s or "").lower()
    return any(k in t for k in SENSITIVE_KEYWORDS)

def exposure_score(port_obj: Dict[str, Any]) -> int:
    score = 0
    port = int(port_obj.get("port", 0))
    service = (port_obj.get("service") or "").lower()

    if port_obj.get("public_scan", True):
        score += 15

    if service in {"http", "https"} and port in NON_STANDARD_WEB_PORTS:
        score += 5

    for e in (port_obj.get("exposure") or []):
        e = str(e).lower()
        if "swagger" in e or "openapi" in e:
            score += 10
        if "admin" in e:
            score += 10

    return int(clamp(score, 0, 35))

def config_score(port_obj: Dict[str, Any]) -> int:
    score = 0
    cfg = port_obj.get("config") or {}
    missing = cfg.get("missing_security_headers") or []

    if missing:
        score += min(6, 2 + len(missing) // 3)
    if cfg.get("deprecated_policy"):
        score += 2

    return int(clamp(score, 0, 20))

def cvss_to_points(cvss: float | None) -> int:
    if cvss is None:
        return 0
    if cvss >= 9.0:
        return 35
    if cvss >= 7.0:
        return 25
    if cvss >= 4.0:
        return 15
    if cvss > 0:
        return 5
    return 0

def vuln_knowledge_score(port_obj: Dict[str, Any]) -> int:
    cves = port_obj.get("cve_matches") or []
    if not cves:
        return 0
    best = 0
    for c in cves:
        cvss = c.get("cvss")
        try:
            cvss = float(cvss) if cvss is not None else None
        except Exception:
            cvss = None
        best = max(best, cvss_to_points(cvss))
    return int(clamp(best, 0, 35))

def functional_score(asset: Dict[str, Any]) -> int:
    score = 0
    eps = asset.get("functional_attack_surface", {}).get("api_endpoints") or []

    unauth = 0
    state_change = 0
    unauth_state = 0
    sensitive = 0

    for ep in eps:
        path = ep.get("path", "")
        auth = bool(ep.get("auth_required", False))
        sc = bool(ep.get("state_change", False))

        if not auth:
            unauth += 1
        if sc:
            state_change += 1
        if (not auth) and sc:
            unauth_state += 1
        if has_kw(path) or has_kw(ep.get("summary","")):
            sensitive += 1

    if unauth > 0:
        score += 6
    if state_change > 0:
        score += 6
    if unauth_state > 0:
        score += 10
    if sensitive > 0:
        score += 4

    return int(clamp(score, 0, 20))

def score_service(asset: Dict[str, Any], port_obj: Dict[str, Any]) -> Dict[str, Any]:
    ex = exposure_score(port_obj)
    cfg = config_score(port_obj)
    vk = vuln_knowledge_score(port_obj)
    fn = functional_score(asset)

    total = int(clamp(ex + cfg + vk + fn, 0, 100))
    if total >= 70:
        level = "Critical"
    elif total >= 40:
        level = "High"
    elif total >= 20:
        level = "Medium"
    else:
        level = "Low"

    return {
        "port": port_obj.get("port"),
        "service": port_obj.get("service"),
        "total": total,
        "level": level,
        "breakdown": {"exposure": ex, "config": cfg, "vuln_knowledge": vk, "functional": fn}
    }

def score_asset(asset: Dict[str, Any]) -> Dict[str, Any]:
    ports = asset.get("technical_attack_surface", {}).get("ports") or []
    per = [score_service(asset, p) for p in ports]
    if not per:
        return {"asset_total": 0, "asset_level": "Low", "services": []}

    max_total = max(s["total"] for s in per)
    bonus = min(10, max(0, len(ports) - 1) * 2)
    asset_total = int(clamp(max_total + bonus, 0, 100))

    if asset_total >= 70:
        lvl = "Critical"
    elif asset_total >= 40:
        lvl = "High"
    elif asset_total >= 20:
        lvl = "Medium"
    else:
        lvl = "Low"

    return {"asset_total": asset_total, "asset_level": lvl, "services": sorted(per, key=lambda x: x["total"], reverse=True)}
