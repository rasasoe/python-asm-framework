from __future__ import annotations

import unittest

from core.asset import new_asset
from report.normalized_findings import build_findings_export
from risk.scoring import score_asset


class FindingsExportTests(unittest.TestCase):
    def test_export_uses_versioned_deterministic_contract(self):
        asset = new_asset("127.0.0.1")
        asset["technical_attack_surface"]["ports"] = [
            {
                "port": 8000,
                "protocol": "tcp",
                "service": "http",
                "product": "uvicorn",
                "version": "0.27",
                "public_scan": False,
                "exposure": ["openapi"],
                "config": {},
                "cve_matches": [],
            }
        ]
        asset["risk_summary"] = score_asset(asset)

        exported = build_findings_export(asset, "2026-01-01T00:00:00+00:00")
        finding = exported["findings"][0]

        self.assertEqual(exported["schema_version"], "1.0")
        self.assertEqual(finding["source"], "python-asm-framework")
        self.assertEqual(finding["asset"]["value"], "127.0.0.1")
        self.assertEqual(
            finding["finding_type"], "attack_surface.service_exposure"
        )
        self.assertEqual(finding["detected_at"], "2026-01-01T00:00:00+00:00")


if __name__ == "__main__":
    unittest.main()

