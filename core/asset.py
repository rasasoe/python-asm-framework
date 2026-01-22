from __future__ import annotations

def new_asset(ip: str, env: str = "local") -> dict:
    return {
        "asset": {
            "type": "host",
            "ip": ip,
            "environment": env
        },
        "technical_attack_surface": {
            "ports": [],
            "os_guess": None,
            "nse_findings": ""
        },
        "functional_attack_surface": {
            "api_endpoints": [],
            "swagger_meta": {},
            "ui_functions": []
        },
        "vulnerability_context": {
            "cve_matches": [],
            "nvd_enriched": [],
            "risk_notes": []
        },
        "risk_summary": {}
    }
