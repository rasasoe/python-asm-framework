from __future__ import annotations

import json
import yaml
from pathlib import Path

from core.asset import new_asset

from scanner.port_scan import scan_services
from scanner.os_fingerprint import detect_os_guess
from scanner.http_probe import probe_http_endpoints, apply_http_findings_to_ports
from scanner.nse_safe import run_nse_safe

from parser.swagger_parser import fetch_and_parse_swagger
from parser.selenium_mapper import collect_ui_functions_observe_only

from vuln.vulners_mapper import map_services_with_vulners
from vuln.nvd_mapper import enrich_cves_with_nvd

from risk.scoring import score_asset
from report.markdown_report import generate_report_md

def load_config(path: str = "config.yaml") -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def ensure_output_dir():
    Path("output").mkdir(parents=True, exist_ok=True)

def main():
    cfg = load_config()
    ensure_output_dir()

    ip = cfg["target"]["ip"]
    base_url = cfg["target"]["base_url"]
    swagger_path = cfg["target"]["swagger_path"]

    asset = new_asset(ip, env=("public" if cfg["risk"].get("public_scan", True) else "local"))

    # 1) Technical: port/service/version
    ports = scan_services(ip)
    for p in ports:
        # 리스크 계산에 사용되는 힌트: public_scan 플래그 주입
        p["public_scan"] = bool(cfg["risk"].get("public_scan", True))
    asset["technical_attack_surface"]["ports"] = ports

    # 2) Technical: OS guess
    asset["technical_attack_surface"]["os_guess"] = detect_os_guess(ip)

    # 3) Technical: HTTP probe (headers + exposures)
    http_findings = probe_http_endpoints(ip, ports, base_url=base_url)
    apply_http_findings_to_ports(asset["technical_attack_surface"]["ports"], http_findings)

    # 4) Optional: NSE safe/discovery
    if cfg["collection"].get("run_nse_safe", False):
        asset["technical_attack_surface"]["nse_findings"] = run_nse_safe(ip)
    else:
        asset["technical_attack_surface"]["nse_findings"] = ""

    # 5) Functional: Swagger API map (structure only)
    swagger_url = base_url.rstrip("/") + swagger_path
    api_eps, swagger_meta = fetch_and_parse_swagger(swagger_url)
    asset["functional_attack_surface"]["api_endpoints"] = api_eps
    asset["functional_attack_surface"]["swagger_meta"] = swagger_meta

    # 6) Functional: Selenium observe-only UI mapping
    if cfg["collection"].get("run_selenium", True):
        ui = collect_ui_functions_observe_only(
            base_url,
            headless=True,
            max_buttons=int(cfg["collection"].get("selenium_max_buttons", 80)),
        )
        asset["functional_attack_surface"]["ui_functions"] = ui
    else:
        asset["functional_attack_surface"]["ui_functions"] = []

    # 7) Vuln knowledge mapping: Vulners
    if cfg["vulners"].get("enabled", False):
        api_key = cfg["vulners"].get("api_key", "").strip()
        asset["technical_attack_surface"]["ports"] = map_services_with_vulners(
            api_key=api_key,
            ports=asset["technical_attack_surface"]["ports"],
            per_service_limit=int(cfg["vulners"].get("per_service_limit", 8)),
        )

    # 8) Aggregate CVEs to vulnerability_context
    all_cves = []
    for p in asset["technical_attack_surface"]["ports"]:
        for c in (p.get("cve_matches") or []):
            all_cves.append({
                "port": p.get("port"),
                "service": p.get("service"),
                "product": p.get("product"),
                "version": p.get("version"),
                **c
            })
    asset["vulnerability_context"]["cve_matches"] = all_cves

    # 9) Optional: NVD enrich top-N CVEs for reporting clarity
    if cfg["nvd"].get("enabled", False) and all_cves:
        nvd_key = cfg["nvd"].get("api_key", "").strip()
        top_n = int(cfg["nvd"].get("enrich_top_n", 5))
        asset["vulnerability_context"]["nvd_enriched"] = enrich_cves_with_nvd(
            cves=all_cves[:top_n],
            api_key=nvd_key if nvd_key else None
        )
    else:
        asset["vulnerability_context"]["nvd_enriched"] = []

    # 10) Risk scoring
    risk = score_asset(asset)
    asset["risk_summary"] = risk

    # Notes
    asset["vulnerability_context"]["risk_notes"].append(
        "CVE mapping is knowledge-based only; no exploitation or intrusive validation performed."
    )

    # Save JSON
    with open("output/result.json", "w", encoding="utf-8") as f:
        json.dump(asset, f, indent=2, ensure_ascii=False)

    # Save report
    report_md = generate_report_md(asset)
    with open("output/report.md", "w", encoding="utf-8") as f:
        f.write(report_md)

    print("[+] Done")
    print(" - output/result.json")
    print(" - output/report.md")

if __name__ == "__main__":
    main()
