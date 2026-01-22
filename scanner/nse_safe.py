from __future__ import annotations

import subprocess

def run_nse_safe(ip: str) -> str:
    """
    NSE는 safe/discovery 범위만 사용.
    OS/환경에 따라 nmap 경로 문제 가능 → config에서 끄는 걸 기본 권장.
    """
    cmd = ["nmap", "-sV", "--script", "safe,discovery", ip]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        out = (p.stdout or "") + ("\n" + p.stderr if p.stderr else "")
        return out.strip()
    except Exception as e:
        return f"[NSE_ERROR] {e}"
