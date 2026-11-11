
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reports import report_generator


class TestReportGenerator(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.output_dir = Path(self.temp_dir.name)

        self.sample_scan_results = [
            {
                "port": 23,
                "protocol": "tcp",
                "state": "open",
                "service": "telnet",
                "product": "Telnet",
                "version": "1.0"
            },
            {
                "port": 443,
                "protocol": "tcp",
                "state": "closed",
                "service": "https",
                "product": "",
                "version": ""
            }
        ]

        self.sample_findings = [
            {
                "port": 23,
                "service": "telnet",
                "severity": "CRITICAL",
                "finding": "Unencrypted remote access service detected",
                "recommendation": "Disable Telnet and use SSH."
            }
        ]

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_build_report_data(self):
        report = report_generator.build_report_data(
            "192.168.1.10",
            "1-1000",
            self.sample_scan_results,
            self.sample_findings
        )

        self.assertEqual(report["application"], "NetAudit CLI")
        self.assertEqual(report["target"], "192.168.1.10")
        self.assertEqual(report["port_range"], "1-1000")
        self.assertEqual(
            report["scan_summary"]["total_ports_identified"], 2
        )
        self.assertEqual(report["scan_summary"]["open_ports"], 1)
        self.assertEqual(report["severity_summary"]["critical"], 1)

    def test_generates_valid_json_report(self):
        with (
            patch.object(
                report_generator,
                "JSON_DIR",
                self.output_dir / "json"
            ),
            patch.object(
                report_generator,
                "HTML_DIR",
                self.output_dir / "html"
            )
        ):
            report_path = report_generator.generate_report(
                "192.168.1.10",
                "1-1000",
                self.sample_scan_results,
                self.sample_findings,
                "json"
            )

            self.assertTrue(report_path.exists())

            with report_path.open("r", encoding="utf-8") as file:
                report = json.load(file)

            self.assertEqual(report["target"], "192.168.1.10")
            self.assertEqual(
                report["scan_summary"]["open_ports"], 1
            )
            self.assertEqual(len(report["security_findings"]), 1)

    def test_generates_html_report(self):
        with (
            patch.object(
                report_generator,
                "JSON_DIR",
                self.output_dir / "json"
            ),
            patch.object(
                report_generator,
                "HTML_DIR",
                self.output_dir / "html"
            )
        ):
            report_path = report_generator.generate_report(
                "192.168.1.10",
                "1-1000",
                self.sample_scan_results,
                self.sample_findings,
                "html"
            )

            self.assertTrue(report_path.exists())

            content = report_path.read_text(encoding="utf-8")

            self.assertIn("<!DOCTYPE html>", content)
            self.assertIn("NetAudit CLI", content)
            self.assertIn("192.168.1.10", content)
            self.assertIn("Security Findings and Recommendations", content)
            self.assertIn("CRITICAL", content)

    def test_html_report_escapes_untrusted_content(self):
        malicious_target = '<script>alert("test")</script>'

        with (
            patch.object(
                report_generator,
                "JSON_DIR",
                self.output_dir / "json"
            ),
            patch.object(
                report_generator,
                "HTML_DIR",
                self.output_dir / "html"
            )
        ):
            report_path = report_generator.generate_report(
                malicious_target,
                "1-1000",
                self.sample_scan_results,
                self.sample_findings,
                "html"
            )

            content = report_path.read_text(encoding="utf-8")

            self.assertNotIn("<script>alert", content)
            self.assertIn("&lt;script&gt;", content)

    def test_rejects_unsupported_report_format(self):
        with self.assertRaises(ValueError):
            report_generator.generate_report(
                "192.168.1.10",
                "1-1000",
                self.sample_scan_results,
                self.sample_findings,
                "pdf"
            )


if __name__ == "__main__":
    unittest.main()
