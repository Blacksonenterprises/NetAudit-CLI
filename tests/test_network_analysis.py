
import unittest

from modules.network_analysis import analyze_network_devices


class TestNetworkAnalysis(unittest.TestCase):

    def setUp(self):
        self.devices = [
            {
                "ip": "192.168.1.1",
                "hostname": "Router",
                "mac": "AA:BB:CC:DD:EE:01",
                "status": "up"
            },
            {
                "ip": "192.168.1.2",
                "hostname": "Laptop",
                "mac": "AA:BB:CC:DD:EE:02",
                "status": "up"
            },
            {
                "ip": "192.168.1.3",
                "hostname": "Unknown",
                "mac": "AA:BB:CC:DD:EE:02",
                "status": "up"
            }
        ]

    def test_network_summary(self):
        result = analyze_network_devices(
            self.devices,
            "192.168.1.0/24"
        )

        self.assertEqual(result["valid_devices"], 3)
        self.assertEqual(result["active_devices"], 3)

    def test_missing_hostname_detection(self):
        result = analyze_network_devices(
            self.devices,
            "192.168.1.0/24"
        )

        self.assertIn(
            "192.168.1.3",
            result["missing_hostnames"]
        )

    def test_duplicate_mac_detection(self):
        result = analyze_network_devices(
            self.devices,
            "192.168.1.0/24"
        )

        self.assertIn(
            "aa:bb:cc:dd:ee:02",
            result["duplicate_mac_addresses"]
        )

    def test_invalid_subnet(self):
        with self.assertRaises(ValueError):
            analyze_network_devices(
                self.devices,
                "invalid-subnet"
            )

    def test_outside_subnet_device(self):
        devices = [
            {
                "ip": "10.0.0.5",
                "hostname": "External Device",
                "mac": "AA:BB:CC:DD:EE:05",
                "status": "up"
            }
        ]

        result = analyze_network_devices(
            devices,
            "192.168.1.0/24"
        )

        self.assertEqual(result["valid_devices"], 0)
        self.assertEqual(
            result["invalid_or_outside_ips"],
            ["10.0.0.5"]
        )


if __name__ == "__main__":
    unittest.main()
