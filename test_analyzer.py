import tempfile
import unittest
from pathlib import Path

from analyzer import analyze_log, generate_markdown_report, parse_log_lines, write_report


class SecureLogAnalyzerTests(unittest.TestCase):
    def test_detects_brute_force_and_encoded_traversal(self) -> None:
        lines = [
            "Oct  2 09:00:00 host sshd[1]: Accepted publickey for alice from 192.0.2.10 port 22 ssh2",
            *(
                f"Oct  2 09:00:0{index} host sshd[{index}]: Failed password for root from 203.0.113.9 port {2200 + index} ssh2"
                for index in range(1, 7)
            ),
            '203.0.113.9 - - [02/Oct/2026:09:01:00 +0000] "GET /%2e%2e/%2e%2e/etc/passwd HTTP/1.1" 400 123 "-" "curl/8.0"',
        ]

        result = parse_log_lines(lines)

        self.assertEqual(len(result.successful_logins), 1)
        self.assertEqual(len(result.failed_logins), 6)
        self.assertEqual(result.brute_force_sources, {"203.0.113.9": 6})
        self.assertEqual(len(result.exploitation_attempts), 1)
        self.assertEqual(result.overall_threat_level, "CRITICAL")

    def test_brute_force_threshold_is_strictly_more_than_five(self) -> None:
        lines = [
            f"Oct  2 09:00:0{index} host sshd[{index}]: Failed password for root from 198.51.100.9 port {2200 + index} ssh2"
            for index in range(1, 6)
        ]

        result = parse_log_lines(lines)

        self.assertEqual(len(result.failed_logins), 5)
        self.assertEqual(result.brute_force_sources, {})
        self.assertEqual(result.overall_threat_level, "MEDIUM")

    def test_report_export_contains_findings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            log_path = directory_path / "events.log"
            report_path = directory_path / "security_incident_report.md"
            log_path.write_text(
                "Oct  2 09:00:00 host sshd[1]: Accepted password for bob from 192.0.2.5 port 22 ssh2\n",
                encoding="utf-8",
            )

            result = analyze_log(log_path)
            written_path = write_report(result, log_path, report_path)

            self.assertEqual(written_path, report_path)
            report = report_path.read_text(encoding="utf-8")
            self.assertIn("# SecureLogAnalyzer Security Incident Report", report)
            self.assertIn("Successful SSH logins:** 1", report)
            self.assertIn("LOW", report)


if __name__ == "__main__":
    unittest.main()
