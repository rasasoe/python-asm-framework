from __future__ import annotations

import nmap

def detect_os_guess(ip: str) -> str:
    """
    OS 추정은 정확도보다 '계열 힌트' 목적.
    권한/환경에 따라 실패할 수 있으므로 안전하게 처리.
    """
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=ip, arguments="-O --osscan-guess")
        if ip in nm.all_hosts():
            osmatch = nm[ip].get("osmatch") or []
            if osmatch:
                return osmatch[0].get("name") or "Unknown"
    except Exception:
        pass
    return "Unknown"
