from __future__ import annotations

from urllib.parse import urlparse


def validate_target_authorization(cfg: dict) -> None:
    """Reject scan and HTTP targets that are outside the explicit allowlist."""
    target_cfg = cfg.get("target") or {}
    scan_target = str(target_cfg.get("ip") or "").strip()
    base_url = str(target_cfg.get("base_url") or "").strip()
    base_url_host = (urlparse(base_url).hostname or "").strip()

    authorization = cfg.get("authorization") or {}
    allowed_targets = {
        str(item).strip()
        for item in authorization.get("allowed_targets", [])
        if str(item).strip()
    }

    if not authorization.get("acknowledged", False):
        raise RuntimeError(
            "Set authorization.acknowledged=true only after confirming target ownership or permission."
        )

    requested_targets = {scan_target, base_url_host}
    if "" in requested_targets:
        raise RuntimeError("Both target.ip and a valid target.base_url are required.")

    unauthorized = sorted(requested_targets - allowed_targets)
    if unauthorized:
        joined = ", ".join(repr(item) for item in unauthorized)
        raise RuntimeError(
            f"Target(s) {joined} are not present in authorization.allowed_targets."
        )
