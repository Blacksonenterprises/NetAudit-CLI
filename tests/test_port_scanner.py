
import subprocess
import unittest
from unittest.mock import patch

from modules.port_scanner import scan_ports


class TestPortScanner(unittest.TestCase):

    SAMPLE_NMAP_XML = """<?xml version="1.0"?>
    <nmaprun>
        <host>
            <address addr="192.168.1.10" addrtype="ipv4"/>
            <ports>
                <port protocol="tcp" portid="22">
                    <state state="open"/>
                    <service name="ssh"
                             product="OpenSSH"
                             version="9.0"/>
                </port>
                <port protocol="tcp" portid="80">
                    <state state="closed"/>
                    <service name="http"/>
                </port>
            </ports>
        </host>
    </nmaprun>
    """

    def test_parses_nmap_port_results(self):
        completed_process = subprocess.CompletedProcess(
            args=["nmap"],
            returncode=0,
            stdout=self.SAMPLE_NMAP_XML,
            stderr=""
        )

        with patch(
            "modules.port_scanner.subprocess.run",
            return_value=completed_process
        ):
            results = scan_ports("192.168.1.10", "22-80")

        self.assertEqual(len(results), 2)

        self.assertEqual(results[0]["port"], 22)
        self.assertEqual(results[0]["protocol"], "tcp")
        self.assertEqual(results[0]["state"], "open")
        self.assertEqual(results[0]["service"], "ssh")
        self.assertEqual(results[0]["product"], "OpenSSH")
        self.assertEqual(results[0]["version"], "9.0")

        self.assertEqual(results[1]["port"], 80)
        self.assertEqual(results[1]["state"], "closed")

    def test_rejects_invalid_target(self):
        with self.assertRaises(ValueError):
            scan_ports("not-an-ip-address", "22")

    def test_rejects_public_ip_target(self):
        with self.assertRaises(ValueError):
            scan_ports("8.8.8.8", "22")

    def test_rejects_invalid_port_input(self):
        with self.assertRaises(ValueError):
            scan_ports("192.168.1.10", "invalid")

    def test_rejects_port_outside_valid_range(self):
        with self.assertRaises(ValueError):
            scan_ports("192.168.1.10", "70000")

    def test_rejects_excessively_large_port_range(self):
        with self.assertRaises(ValueError):
            scan_ports("192.168.1.10", "1-10001")

    def test_handles_missing_nmap(self):
        with patch(
            "modules.port_scanner.subprocess.run",
            side_effect=FileNotFoundError
        ):
            with self.assertRaises(RuntimeError):
                scan_ports("192.168.1.10", "22")

    def test_handles_malformed_nmap_xml(self):
        completed_process = subprocess.CompletedProcess(
            args=["nmap"],
            returncode=0,
            stdout="<nmaprun><host>",
            stderr=""
        )

        with patch(
            "modules.port_scanner.subprocess.run",
            return_value=completed_process
        ):
            with self.assertRaises(RuntimeError):
                scan_ports("192.168.1.10", "22")


if __name__ == "__main__":
    unittest.main()
