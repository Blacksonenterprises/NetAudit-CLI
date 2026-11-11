
import sys
import unittest
from unittest.mock import patch
from contextlib import redirect_stdout, redirect_stderr
from io import StringIO

import main


class TestNetAuditCLI(unittest.TestCase):

    def setUp(self):
        self.banner_patch = patch("main.display_banner")
        self.status_patch = patch("main.display_status")

        self.banner_patch.start()
        self.status_patch.start()

    def tearDown(self):
        self.banner_patch.stop()
        self.status_patch.stop()

    @patch("main.run_discovery")
    def test_discover_command(self, mock_discovery):
        with patch.object(
            sys, "argv",
            ["netaudit", "discover", "--subnet", "192.168.1.0/24"]
        ):
            main.main()

        mock_discovery.assert_called_once_with("192.168.1.0/24")

    @patch("main.run_port_scan")
    def test_scan_command(self, mock_scan):
        with patch.object(
            sys, "argv",
            ["netaudit", "scan", "--target", "192.168.1.10", "--ports", "22-80"]
        ):
            main.main()

        mock_scan.assert_called_once_with("192.168.1.10", "22-80")

    @patch("main.run_report")
    def test_report_command(self, mock_report):
        with patch.object(
            sys, "argv",
            [
                "netaudit", "report",
                "--target", "192.168.1.10",
                "--ports", "1-1000",
                "--format", "html"
            ]
        ):
            main.main()

        mock_report.assert_called_once_with(
            "192.168.1.10", "1-1000", "html"
        )

    @patch("main.show_history")
    def test_history_command(self, mock_history):
        with patch.object(sys, "argv", ["netaudit", "history"]):
            main.main()

        mock_history.assert_called_once()

    def test_version_argument(self):
        output = StringIO()

        with patch.object(sys, "argv", ["netaudit", "--version"]):
            with redirect_stdout(output):
                with self.assertRaises(SystemExit) as error:
                    main.main()

        self.assertEqual(error.exception.code, 0)
        self.assertIn(main.VERSION, output.getvalue())

    def test_invalid_command_is_rejected(self):
        error_output = StringIO()

        with patch.object(sys, "argv", ["netaudit", "invalid-command"]):
            with redirect_stderr(error_output):
                with self.assertRaises(SystemExit) as error:
                    main.main()

        self.assertEqual(error.exception.code, 2)
        self.assertIn("invalid choice", error_output.getvalue())


if __name__ == "__main__":
    unittest.main()
