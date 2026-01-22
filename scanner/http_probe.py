from __future__ import annotations

from typing import Dict, Any, List, Optional
import requests

NON_STANDARD_WEB_PORTS = {3000, 8000, 8080, 8888, 5000, 7001, 9000}

def _looks_like_http_service(p: dict) -> bool:
    svc = (p.get("service") or "").lower()
    return svc in {"http", "https", "http-alt", "http-proxy"} or p.get("port") in NON_STANDARD_WEB_PORTS

def probe_http_endpoints(ip: str, ports: List[dict], base_url: str) -> Dict[int, Dict[str, Any]]:
    """
    공격이 아니라 'HEAD/GET로 헤더 관찰' 수준의 프로빙.
    - Server / X-Powered-By 등 배너 보강
    - 보안헤더 누락 체크(간단)
    - Swagger/OpenAPI 노출 여부 힌트
    """
    findings: Dict[int, Dict[str, Any]] = {}

    for p in ports:
        port = int(p.get("port"))
        if not _looks_like_http_service(p):
            continue

        # base_url이 해당 포트를 가리키는 경우 우선 사용, 아니면 http://ip:port 시도
        url = base_url.rstrip("/")
        if f":{port}" not in url:
            url = f"http://{ip}:{port}"

        f: Dict[str, Any] = {"url": url, "headers": {}, "status": None, "exposure": [], "missing_headers": []}

        try:
            r = requests.get(url, timeout=5, allow_redirects=True)
            f["status"] = r.status_code
            f["headers"] = dict(r.headers)
        except Exception as e:
            f["error"] = str(e)
            findings[port] = f
            continue

        hdr = {k.lower(): v for k, v in f["headers"].items()}

        # minimal security header checklist
        sec_headers = [
            "content-security-policy",
            "strict-transport-security",
            "permissions-policy",
            "referrer-policy",
            "x-content-type-options",
            "x-frame-options",
        ]
        missing = [h for h in sec_headers if h not in hdr]
        f["missing_headers"] = missing

        # swagger/openapi exposure heuristic (존재 확인용)
        # (실제 파일을 읽는 건 swagger_parser에서 수행)
        if "swagger" in (hdr.get("x-powered-by", "") or "").lower():
            f["exposure"].append("swagger-hint")

        findings[port] = f

    return findings

def apply_http_findings_to_ports(ports: List[dict], findings: Dict[int, Dict[str, Any]]) -> None:
    for p in ports:
        port = int(p.get("port"))
        if port not in findings:
            continue

        f = findings[port]
        hdr = {k.lower(): v for k, v in (f.get("headers") or {}).items()}

        # config 반영
        p["config"]["http_status"] = f.get("status")
        p["config"]["server_header"] = hdr.get("server", "")
        p["config"]["x_powered_by"] = hdr.get("x-powered-by", "")
        p["config"]["missing_security_headers"] = f.get("missing_headers", [])
        p["config"]["deprecated_policy"] = "feature-policy" in hdr

        # exposure 반영 (swagger는 swagger_parser에서 최종 확정하지만, 포트 레벨 힌트는 남김)
        for e in f.get("exposure", []):
            if e not in p["exposure"]:
                p["exposure"].append(e)
