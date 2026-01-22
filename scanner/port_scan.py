from __future__ import annotations

import nmap

def scan_services(ip: str) -> list[dict]:
    nm = nmap.PortScanner()
    # ASM 친화: -sV + version-light (과도한 probe 줄임)
    nm.scan(hosts=ip, arguments="-Pn -p- -sV --version-light")

    ports: list[dict] = []
    if ip not in nm.all_hosts():
        return ports

    for proto in nm[ip].all_protocols():
        for port in nm[ip][proto]:
            info = nm[ip][proto][port]
            if info.get("state") != "open":
                continue

            ports.append({
                "port": int(port),
                "protocol": proto,
                "service": info.get("name") or "",
                "product": info.get("product") or "",
                "version": info.get("version") or "",
                "extrainfo": info.get("extrainfo") or "",
                "exposure": [],
                "config": {},
                "cve_matches": []
            })
    return sorted(ports, key=lambda x: (x["protocol"], x["port"]))
