import tempfile
import unittest
from pathlib import Path

from security_audit import audit_repository


class SecurityAuditTests(unittest.TestCase):
    def test_clean_repository_scores_100(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "safe.py").write_text("print('safe')\n", encoding="utf-8")
            result = audit_repository(root)
            self.assertTrue(result.passed)
            self.assertEqual(result.score, 100)

    def test_secret_pattern_fails_without_exposing_value(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "config.py").write_text(
                'api_key = "abcdefghijklmnopqrstuvwx"\n', encoding="utf-8"
            )
            result = audit_repository(root)
            self.assertFalse(result.passed)
            self.assertLess(result.score, 100)
            self.assertEqual(result.findings[0].rule, "generic_api_key")
            self.assertNotIn("abcdefghijklmnopqrstuvwx", result.findings[0].message)

    def test_forbidden_sensitive_filename_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / ".env").write_text("SAFE_PLACEHOLDER=true\n", encoding="utf-8")
            result = audit_repository(root)
            self.assertFalse(result.passed)
            self.assertEqual(result.findings[0].rule, "forbidden_sensitive_file")

    def test_allow_marker_suppresses_known_test_fixture(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "fixture.py").write_text(
                'api_key = "abcdefghijklmnopqrstuvwx"  # security-audit: allow\n',
                encoding="utf-8",
            )
            result = audit_repository(root)
            self.assertTrue(result.passed)
            self.assertEqual(result.score, 100)


if __name__ == "__main__":
    unittest.main()
