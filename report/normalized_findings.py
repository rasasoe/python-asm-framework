from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict


SCHEMA_VERSION = "1.0"


def _confidence(port: Dict[str, Any]) -> tuple[float, str]:
    cves = port.get("cve_matches") or []
    if cves:
        return 0.9, "service fingerprint with CVE knowledge mapping"
    if port.get("product") and port.get("version"):
        return 0.75, "product and version fingerprint"
    if port.get("service"):
        return 0.6, "service fingerprint"
    return 0.4, "open-port observation"


def build_findings_export(
    asset: Dict[str, Any], detected_at: str | None = None
) -> Dict[str, Any]:
    """Convert an ASM result into the portfolio's versioned finding contract."""
    generated_at = detected_at or datetime.now(timezone.utc).isoformat()
    asset_meta = asset.get("asset") or {}
    ports = asset.get("technical_attack_surface", {}).get("ports") or []
    risk_services = {
        (item.get("port"), item.get("service")): item
        for item in (asset.get("risk_summary", {}).get("services") or [])
    }

    findings = []
    for port in ports:
        key = (port.get("port"), port.get("service"))
        risk = risk_services.get(key, {})
        confidence, confidence_basis = _confidence(port)
        cves = port.get("cve_matches") or []

        findings.append(
            {
                "source": "python-asm-framework",
                "asset": {
                    "type": asset_meta.get("type", "host"),
                    "value": asset_meta.get("ip", ""),
                    "environment": asset_meta.get("environment", "local"),
                },
                "finding_type": "attack_surface.service_exposure",
                "title": (
                    f"Exposed {port.get('service') or 'service'} on "
                    f"{port.get('port')}/{port.get('protocol') or 'tcp'}"
                ),
                "severity": (risk.get("level") or "Low").lower(),
                "score": int(risk.get("total") or 0),
                "confidence": confidence,
                "confidence_basis": confidence_basis,
                "evidence": {
                    "port": port.get("port"),
                    "protocol": port.get("protocol"),
                    "service": port.get("service"),
                    "product": port.get("product"),
                    "version": port.get("version"),
                    "exposure": port.get("exposure") or [],
                    "risk_breakdown": risk.get("breakdown") or {},
                },
                "references": [
                    ref
                    for cve in cves
                    for ref in [cve.get("href") or cve.get("cve")]
                    if ref
                ],
                "detected_at": generated_at,
            }
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "findings": findings,
    }

