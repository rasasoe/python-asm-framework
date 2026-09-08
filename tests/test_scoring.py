from __future__ import annotations

import unittest

from core.asset import new_asset
from risk.scoring import score_asset


class RiskScoringTests(unittest.TestCase):
    def test_empty_asset_is_low_risk(self):
        result = score_asset(new_asset("127.0.0.1"))

        self.assertEqual(result["asset_total"], 0)
        self.assertEqual(result["asset_level"], "Low")
        self.assertEqual(result["services"], [])

    def test_exposure_and_cve_context_raise_service_risk(self):
        asset = new_asset("127.0.0.1")
        asset["technical_attack_surface"]["ports"] = [
            {
                "port": 8080,
                "protocol": "tcp",
                "service": "http",
                "public_scan": True,
                "exposure": ["swagger exposed"],
                "config": {"missing_security_headers": ["csp", "hsts"]},
                "cve_matches": [{"cve": "CVE-TEST", "cvss": 9.1}],
            }
        ]

        result = score_asset(asset)

        self.assertEqual(result["asset_level"], "High")
        self.assertGreaterEqual(result["services"][0]["total"], 40)


if __name__ == "__main__":
    unittest.main()

