from __future__ import annotations

from typing import Any, Dict, List
from datetime import datetime, timezone

def esc(s: str) -> str:
    return (s or "").replace("|", "\\|")

def ports_table(ports: List[Dict[str, Any]]) -> str:
    lines = [
        "| Port | Proto | Service | Product | Version | Exposures |",
        "|---:|:---:|:---|:---|:---|:---|"
    ]
    for p in ports:
        lines.append(
            f"| {p.get('port')} | {esc(str(p.get('protocol','')))} | {esc(str(p.get('service','')))} | "
            f"{esc(str(p.get('product','')))} | {esc(str(p.get('version','')))} | "
            f"{esc(', '.join(p.get('exposure', []) or []))} |"
        )
    return "\n".join(lines)

def api_table(eps: List[Dict[str, Any]], limit: int = 60) -> str:
    lines = ["| Method | Path | Auth | State Change |", "|:---:|:---|:---:|:---:|"]
    for ep in eps[:limit]:
        lines.append(
            f"| {esc(ep.get('method',''))} | {esc(ep.get('path',''))} | "
            f"{'Yes' if ep.get('auth_required') else 'No'} | "
            f"{'Yes' if ep.get('state_change') else 'No'} |"
        )
    if len(eps) > limit:
        lines.append(f"\n> endpoints {len(eps)}개 중 상위 {limit}개만 표시.")
    return "\n".join(lines)

def cve_table(cves: List[Dict[str, Any]], limit: int = 30) -> str:
    if not cves:
        return "_No CVE knowledge matches found._"
    lines = ["| Port | CVE | CVSS | Ref |", "|---:|:---|:---:|:---|"]
    for c in cves[:limit]:
        lines.append(
            f"| {c.get('port','-')} | {esc(c.get('cve',''))} | {esc(str(c.get('cvss','-')))} | {esc(c.get('href','-') or '-') } |"
        )
    if len(cves) > limit:
        lines.append(f"\n> CVE {len(cves)}개 중 상위 {limit}개만 표시.")
    return "\n".join(lines)

def generate_report_md(asset: Dict[str, Any]) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    ip = asset.get("asset", {}).get("ip", "-")
    env = asset.get("asset", {}).get("environment", "-")

    ports = asset.get("technical_attack_surface", {}).get("ports", []) or []
    os_guess = asset.get("technical_attack_surface", {}).get("os_guess", "Unknown")
    eps = asset.get("functional_attack_surface", {}).get("api_endpoints", []) or []
    swagger_meta = asset.get("functional_attack_surface", {}).get("swagger_meta", {}) or {}
    ui = asset.get("functional_attack_surface", {}).get("ui_functions", []) or []
    cves = asset.get("vulnerability_context", {}).get("cve_matches", []) or []
    risk = asset.get("risk_summary", {}) or {}

    md: List[str] = []
    md.append("# ASM 실습 보고서\n")
    md.append(f"- 대상 자산: `{ip}`\n- 환경: `{env}`\n- 생성 시각: {now}\n")

    md.append("## 1. 범위 및 원칙\n")
    md.append("- 본 결과는 **공격 표면(노출 서비스/기능 구조) 식별** 및 공개 DB 기반 **지식 매핑**에 한정한다.\n"
              "- 취약점 공격(Exploit), 인증 우회, 데이터 변조 등 침해 행위는 수행하지 않았다.\n")

    md.append("## 2. 기술적 공격 표면(Technical)\n")
    md.append(f"- OS 추정: **{os_guess}**\n")
    md.append("### 2.1 노출 포트/서비스\n")
    md.append(ports_table(ports) + "\n")

    md.append("## 3. 기능적 공격 표면(Functional)\n")
    md.append("### 3.1 Swagger/OpenAPI 기반 API 구조\n")
    md.append(f"- Swagger URL: `{swagger_meta.get('swagger_url','')}`\n")
    md.append(f"- Available: `{swagger_meta.get('available', False)}` | Title: `{swagger_meta.get('title','')}` | Version: `{swagger_meta.get('version','')}`\n")
    md.append(api_table(eps) + "\n")

    if ui:
        md.append("### 3.2 UI 기능(관찰-only)\n")
        md.append("- 클릭/입력 없이 화면에 표시된 버튼/링크 텍스트를 수집하였다.\n")
        for t in ui:
            md.append(f"- {t}")
        md.append("")

    md.append("## 4. 취약점 지식 매핑(Knowledge Mapping)\n")
    md.append(cve_table(cves) + "\n")

    md.append("## 5. 리스크 요약\n")
    md.append(f"- Asset Risk: **{risk.get('asset_level','-')} ({risk.get('asset_total','-')}/100)**\n")
    md.append("### 5.1 서비스별 상위 위험(Top 5)\n")
    for s in (risk.get("services") or [])[:5]:
        b = s.get("breakdown", {})
        md.append(
            f"- Port {s.get('port')}/{s.get('service')}: **{s.get('level')} ({s.get('total')}/100)** "
            f"(Exposure {b.get('exposure')}, Config {b.get('config')}, Knowledge {b.get('vuln_knowledge')}, Functional {b.get('functional')})"
        )
    md.append("")

    md.append("## 6. 결론\n")
    md.append("- 포트/서비스 노출과 기능 구조(Swagger/UI)를 기반으로 공격 표면을 구조적으로 모델링하였다.\n"
              "- CVE는 '존재=침해 성공'이 아니며, 노출(Exposure) 및 구성(Config)과 결합해 해석해야 한다.\n")

    return "\n".join(md)
