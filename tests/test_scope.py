import unittest

from core.scope import validate_target_authorization


class TargetScopeTests(unittest.TestCase):
    def test_accepts_scan_and_http_hosts_in_allowlist(self):
        cfg = {
            "target": {
                "ip": "127.0.0.1",
                "base_url": "http://127.0.0.1:3000",
            },
            "authorization": {
                "acknowledged": True,
                "allowed_targets": ["127.0.0.1"],
            },
        }

        validate_target_authorization(cfg)

    def test_rejects_http_host_outside_allowlist(self):
        cfg = {
            "target": {
                "ip": "127.0.0.1",
                "base_url": "https://example.invalid",
            },
            "authorization": {
                "acknowledged": True,
                "allowed_targets": ["127.0.0.1"],
            },
        }

        with self.assertRaisesRegex(RuntimeError, "example.invalid"):
            validate_target_authorization(cfg)

    def test_rejects_unacknowledged_scope(self):
        cfg = {
            "target": {
                "ip": "127.0.0.1",
                "base_url": "http://127.0.0.1:3000",
            },
            "authorization": {
                "acknowledged": False,
                "allowed_targets": ["127.0.0.1"],
            },
        }

        with self.assertRaisesRegex(RuntimeError, "acknowledged=true"):
            validate_target_authorization(cfg)


if __name__ == "__main__":
    unittest.main()
