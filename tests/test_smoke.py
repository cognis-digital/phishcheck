"""Smoke tests for PHISHCHECK. Stdlib only, no network."""
import io
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from phishcheck import (  # noqa: E402
    score_url, score_email, TOOL_NAME, TOOL_VERSION,
)
from phishcheck.cli import main  # noqa: E402


class UrlTests(unittest.TestCase):
    def test_clean_url(self):
        v = score_url("https://www.github.com/anthropics")
        self.assertEqual(v.verdict, "clean")
        self.assertEqual(v.score, 0)

    def test_typosquat_is_high(self):
        v = score_url("http://paypal-secure-login.account-verify.xyz/verify?id=1")
        self.assertEqual(v.verdict, "high")
        names = {s[0] for s in v.signals}
        self.assertIn("brand-lookalike", names)
        self.assertIn("risky-tld", names)
        self.assertIn("no-tls", names)

    def test_userinfo_and_ip(self):
        v = score_url("https://paypal.com@198.51.100.7/login")
        names = {s[0] for s in v.signals}
        self.assertIn("userinfo-host", names)
        self.assertIn("ip-host", names)
        self.assertNotEqual(v.verdict, "clean")

    def test_punycode(self):
        v = score_url("https://xn--pypal-4ve.com/login")
        self.assertIn("punycode", {s[0] for s in v.signals})

    def test_shortener(self):
        v = score_url("https://bit.ly/abc123")
        self.assertIn("shortener", {s[0] for s in v.signals})


class EmailTests(unittest.TestCase):
    def _load_demo(self):
        path = os.path.join(os.path.dirname(__file__), "..",
                            "demos", "01-basic", "sample_phish.eml")
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()

    def test_phish_email_high(self):
        v = score_email(self._load_demo())
        self.assertEqual(v.verdict, "high")
        names = {s[0] for s in v.signals}
        self.assertIn("dmarc-fail", names)
        self.assertIn("displayname-spoof", names)
        self.assertIn("returnpath-mismatch", names)
        self.assertIn("embedded-url", names)

    def test_benign_email_clean(self):
        raw = (
            "From: Alice <alice@example.com>\n"
            "Return-Path: <alice@example.com>\n"
            "To: bob@example.com\n"
            "Subject: Lunch tomorrow?\n"
            "Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n"
            "\n"
            "Want to grab lunch tomorrow around noon?\n"
        )
        v = score_email(raw)
        self.assertEqual(v.verdict, "clean")


class CliTests(unittest.TestCase):
    def test_version_constants(self):
        self.assertEqual(TOOL_NAME, "phishcheck")
        self.assertTrue(TOOL_VERSION)

    def test_main_url_exit_code(self):
        rc = main(["--format", "json", "url",
                   "http://paypal-secure-login.account-verify.xyz/verify"])
        self.assertEqual(rc, 3)

    def test_main_clean_exit_zero(self):
        rc = main(["url", "https://www.github.com"])
        self.assertEqual(rc, 0)

    def test_main_email_stdin(self):
        raw = (
            "From: Alice <alice@example.com>\n"
            "Return-Path: <alice@example.com>\n"
            "Subject: hi\n\nhello\n"
        )
        old = sys.stdin
        sys.stdin = io.StringIO(raw)
        try:
            rc = main(["email", "-"])
        finally:
            sys.stdin = old
        self.assertEqual(rc, 0)


class HardeningTests(unittest.TestCase):
    """Edge-case and error-path tests added during production hardening."""

    # --- score_url input validation ---

    def test_score_url_none_raises_typeerror(self):
        """Non-string input must raise TypeError, not AttributeError."""
        with self.assertRaises(TypeError):
            score_url(None)

    def test_score_url_non_string_raises_typeerror(self):
        with self.assertRaises(TypeError):
            score_url(42)

    def test_score_url_empty_string_not_clean(self):
        """An empty URL is unparseable and must not score as clean (score > 0)."""
        v = score_url("")
        self.assertGreater(v.score, 0)
        signal_names = {s[0] for s in v.signals}
        self.assertIn("unparsable", signal_names)

    # --- score_email input validation ---

    def test_score_email_non_string_raises_typeerror(self):
        with self.assertRaises(TypeError):
            score_email(42)

    # --- CLI error paths ---

    def test_cli_missing_file_returns_1(self):
        """Passing a path to a file that does not exist must return exit code 1."""
        rc = main(["email", "/nonexistent/__no_such_file__.eml"])
        self.assertEqual(rc, 1)

    def test_cli_blank_url_returns_1(self):
        """A blank URL argument must produce exit code 1, not a silent 'clean'."""
        rc = main(["url", "   "])
        self.assertEqual(rc, 1)

    def test_cli_empty_email_stdin_returns_1(self):
        """Empty stdin for the email subcommand must return exit code 1."""
        old = sys.stdin
        sys.stdin = io.StringIO("   ")
        try:
            rc = main(["email", "-"])
        finally:
            sys.stdin = old
        self.assertEqual(rc, 1)

    def test_cli_json_format_url_output(self):
        """--format json must produce valid JSON with the expected keys."""
        import contextlib
        import json
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            main(["--format", "json", "url", "https://bit.ly/abc"])
        data = json.loads(buf.getvalue())
        self.assertIn("verdict", data)
        self.assertIn("score", data)
        self.assertIn("signals", data)


if __name__ == "__main__":
    unittest.main()
