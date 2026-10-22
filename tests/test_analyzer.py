
import json
import sys
import tempfile
import unittest
from email import policy
from email.parser import BytesParser
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import main


class TestPhishingEmailAnalyzer(unittest.TestCase):

    def create_email(self, raw_email):
        return BytesParser(
            policy=policy.default
        ).parsebytes(raw_email.encode("utf-8"))

    def test_detects_suspicious_phrases_and_urls(self):
        raw_email = """From: Security Team <security@example.test>
Subject: Urgent: Verify your account
Content-Type: text/plain; charset="utf-8"

Please verify your account at http://192.0.2.10/login
or https://bit.ly/example-test.
"""
        results = main.analyze_email(self.create_email(raw_email))

        self.assertEqual(len(results["phrase_findings"]), 2)
        self.assertEqual(len(results["urls"]), 2)
        self.assertEqual(results["risk_score"], 5)
        self.assertEqual(results["risk_level"], "Medium")

    def test_clean_email_has_low_risk(self):
        raw_email = """From: colleague@example.test
Subject: Meeting notes
Content-Type: text/plain; charset="utf-8"

Hello, here are the notes from our meeting.
"""
        results = main.analyze_email(self.create_email(raw_email))

        self.assertEqual(results["risk_score"], 0)
        self.assertEqual(results["risk_level"], "Low")
        self.assertEqual(results["phrase_findings"], [])
        self.assertEqual(results["url_findings"], [])
        self.assertEqual(results["sender_findings"], [])

    def test_missing_email_file_raises_error(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            missing_path = Path(temp_dir) / "missing.eml"

            with self.assertRaises(FileNotFoundError):
                main.load_email(missing_path)

    def test_report_is_saved_as_json(self):
        raw_email = """From: colleague@example.test
Subject: Meeting notes
Content-Type: text/plain; charset="utf-8"

Hello, here are the notes from our meeting.
"""
        results = main.analyze_email(self.create_email(raw_email))

        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.object(main, "REPORT_DIR", Path(temp_dir)):
                report_path = main.save_report(
                    results,
                    Path("test_email.eml"),
                )

                self.assertTrue(report_path.is_file())

                with report_path.open(
                    "r", encoding="utf-8"
                ) as report_file:
                    report = json.load(report_file)

                self.assertEqual(
                    report["email_analysis"]["risk_level"],
                    "Low",
                )
                self.assertIn("disclaimer", report)

    def test_sender_address_is_analyzed(self):
        findings = main.analyze_sender(
            "Security Team <security@example.test>"
        )
        self.assertEqual(findings, [])

    def test_missing_sender_address_is_flagged(self):
        findings = main.analyze_sender("Unknown")
        self.assertTrue(findings)
        self.assertIn("missing", findings[0].lower())

    def test_authentication_results_are_detected(self):
        raw_email = """From: analyst@example.test
Subject: Authentication test
Authentication-Results: mx.example.test; spf=pass; dkim=pass; dmarc=pass
Content-Type: text/plain; charset="utf-8"

This is a test message.
"""
        results = main.analyze_email(self.create_email(raw_email))
        auth_results = results["authentication_analysis"]["results"]

        self.assertIn("pass", auth_results["spf"])
        self.assertIn("pass", auth_results["dkim"])
        self.assertIn("pass", auth_results["dmarc"])

    def test_missing_authentication_header_is_reported(self):
        raw_email = """From: analyst@example.test
Subject: Missing authentication header
Content-Type: text/plain; charset="utf-8"

This is a test message.
"""
        results = main.analyze_email(self.create_email(raw_email))
        authentication = results["authentication_analysis"]

        self.assertEqual(authentication["results"]["spf"], [])
        self.assertEqual(authentication["results"]["dkim"], [])
        self.assertEqual(authentication["results"]["dmarc"], [])

        self.assertTrue(
            any(
                "No Authentication-Results header" in finding
                for finding in authentication["findings"]
            )
        )

    def test_recommendations_are_generated(self):
        raw_email = """From: Security Team <security@example.test>
Subject: Urgent: Verify your account
Content-Type: text/plain; charset="utf-8"

Please verify your account at https://bit.ly/example-test.
"""
        results = main.analyze_email(self.create_email(raw_email))

        self.assertTrue(results["recommendations"])
        self.assertTrue(
            any(
                "URL" in recommendation
                for recommendation in results["recommendations"]
            )
        )

    def test_clean_email_gets_general_recommendation(self):
        raw_email = """From: colleague@example.test
Subject: Meeting notes
Authentication-Results: mx.example.test; spf=pass; dkim=pass; dmarc=pass
Content-Type: text/plain; charset="utf-8"

Here are the meeting notes.
"""
        results = main.analyze_email(self.create_email(raw_email))

        self.assertTrue(results["recommendations"])
        self.assertTrue(
            any(
                "No configured indicators" in recommendation
                for recommendation in results["recommendations"]
            )
        )

    def test_reply_to_domain_mismatch_is_detected(self):
        raw_email = """From: Support <support@company.example>
Reply-To: attacker@unrelated.example
Subject: Account notice
Content-Type: text/plain; charset="utf-8"

Please review your account.
"""
        results = main.analyze_email(self.create_email(raw_email))

        self.assertTrue(results["reply_to_findings"])
        self.assertIn(
            "differs",
            results["reply_to_findings"][0],
        )

    def test_matching_reply_to_domain_is_not_flagged(self):
        raw_email = """From: Support <support@company.example>
Reply-To: help@company.example
Subject: Account notice
Content-Type: text/plain; charset="utf-8"

Please review your account.
"""
        results = main.analyze_email(self.create_email(raw_email))

        self.assertEqual(results["reply_to_findings"], [])

    def test_html_link_destination_mismatch_is_detected(self):
        raw_email = """From: sender@company.example
Subject: HTML link test
MIME-Version: 1.0
Content-Type: text/html; charset="utf-8"

<html><body>
<a href="https://destination.example/login">
https://different.example/login
</a>
</body></html>
"""
        results = main.analyze_email(self.create_email(raw_email))

        self.assertTrue(
            any(
                "different host" in finding.lower()
                for finding in results["html_findings"]
            )
        )


if __name__ == "__main__":
    unittest.main()
