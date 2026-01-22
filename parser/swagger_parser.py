from __future__ import annotations

from typing import Any, Dict, List, Tuple
import requests
import yaml

def fetch_and_parse_swagger(swagger_url: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Swagger(OpenAPI) 문서를 '읽어서' 기능적 공격표면(엔드포인트 구조)만 추출.
    공격/변조/테스트 X
    """
    meta: Dict[str, Any] = {"swagger_url": swagger_url, "available": False}
    endpoints: List[Dict[str, Any]] = []

    try:
        r = requests.get(swagger_url, timeout=7)
        r.raise_for_status()
        spec = yaml.safe_load(r.text)
        meta["available"] = True
    except Exception as e:
        meta["error"] = str(e)
        return endpoints, meta

    # swagger/openapi 메타
    meta["title"] = (spec.get("info") or {}).get("title", "")
    meta["version"] = (spec.get("info") or {}).get("version", "")
    meta["openapi"] = spec.get("openapi") or spec.get("swagger") or ""

    paths = spec.get("paths") or {}
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for m, detail in methods.items():
            if m.lower() not in {"get", "post", "put", "delete", "patch", "head", "options"}:
                continue
            detail = detail or {}
            endpoints.append({
                "path": path,
                "method": m.upper(),
                "auth_required": bool(detail.get("security")),
                "state_change": m.lower() in {"post", "put", "delete", "patch"},
                "summary": detail.get("summary", "") if isinstance(detail, dict) else ""
            })

    return endpoints, meta
