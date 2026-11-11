
import subprocess
import unittest
from unittest.mock import patch

from modules.discovery import discover_devices


class TestNetworkDiscovery(unittest.TestCase):

    SAMPLE_NMAP_XML = """<?xml version="1.0"?>
    <nmaprun>
        <host>
            <status state="up"/>
            <address addr="192.168.1.10" addrtype="ipv4"/>
            <address addr="AA:BB:CC:DD:EE:01" addrtype="mac"/>
            <hostnames>
                <hostname name="device-one" type="PTR"/>
            </hostnames>
        </host>
        <host>
            <status state="up"/>
            <address addr="192.168.1.20" addrtype="ipv4"/>
        </host>
    </nmaprun>
    """

    def test_discovers_devices_from_nmap_xml(self):
        completed_process = subprocess.CompletedProcess(
            args=["nmap"],
            returncode=0,
            stdout=self.SAMPLE_NMAP_XML,
            stderr=""
        )

        with patch(
            "modules.discovery.subprocess.run",
            return_value=completed_process
        ):
            devices = discover_devices("192.168.1.0/24")

        self.assertEqual(len(devices), 2)
        self.assertEqual(devices[0]["ip"], "192.168.1.10")
        self.assertEqual(devices[0]["hostname"], "device-one")
        self.assertEqual(
            devices[0]["mac"],
            "AA:BB:CC:DD:EE:01"
        )
        self.assertEqual(devices[0]["status"], "up")
        self.assertEqual(devices[1]["ip"], "192.168.1.20")

    def test_rejects_invalid_subnet(self):
        with self.assertRaises(ValueError):
            discover_devices("invalid-subnet")

    def test_rejects_public_subnet(self):
        with self.assertRaises(ValueError):
            discover_devices("8.8.8.0/24")

    def test_rejects_oversized_subnet(self):
        with self.assertRaises(ValueError):
            discover_devices("192.168.0.0/16")

    def test_handles_missing_nmap(self):
        with patch(
            "modules.discovery.subprocess.run",
            side_effect=FileNotFoundError
        ):
            with self.assertRaises(RuntimeError):
                discover_devices("192.168.1.0/24")

    def test_handles_malformed_nmap_xml(self):
        completed_process = subprocess.CompletedProcess(
            args=["nmap"],
            returncode=0,
            stdout="<nmaprun><host>",
            stderr=""
        )

        with patch(
            "modules.discovery.subprocess.run",
            return_value=completed_process
        ):
            with self.assertRaises(RuntimeError):
                discover_devices("192.168.1.0/24")


if __name__ == "__main__":
    unittest.main()
