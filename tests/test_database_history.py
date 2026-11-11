
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from database import history


class TestDatabaseHistory(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temp_dir.name) / "test_netaudit.db"

        self.devices = [
            {
                "ip": "192.168.1.10",
                "hostname": "device-one",
                "mac": "AA:BB:CC:DD:EE:01",
                "status": "up"
            },
            {
                "ip": "192.168.1.20",
                "hostname": "device-two",
                "mac": "AA:BB:CC:DD:EE:02",
                "status": "up"
            }
        ]

        self.database_patch = patch.object(
            history,
            "DATABASE_PATH",
            self.database_path
        )
        self.database_patch.start()

    def tearDown(self):
        self.database_patch.stop()
        self.temp_dir.cleanup()

    def test_save_scan_returns_scan_id(self):
        scan_id = history.save_scan(
            "192.168.1.0/24",
            self.devices
        )

        self.assertIsNotNone(scan_id)
        self.assertIsInstance(scan_id, int)

    def test_saved_scan_appears_in_history(self):
        history.save_scan(
            "192.168.1.0/24",
            self.devices
        )

        scans = history.get_scan_history()

        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0]["subnet"], "192.168.1.0/24")
        self.assertEqual(scans[0]["device_count"], 2)

    def test_saved_devices_can_be_retrieved(self):
        scan_id = history.save_scan(
            "192.168.1.0/24",
            self.devices
        )

        saved_devices = history.get_scan_devices(scan_id)

        self.assertEqual(len(saved_devices), 2)
        self.assertEqual(
            saved_devices[0]["ip"],
            "192.168.1.10"
        )
        self.assertEqual(
            saved_devices[1]["ip"],
            "192.168.1.20"
        )

    def test_multiple_scans_are_returned_newest_first(self):
        history.save_scan(
            "192.168.1.0/24",
            self.devices
        )

        history.save_scan(
            "10.0.0.0/24",
            self.devices[:1]
        )

        scans = history.get_scan_history()

        self.assertEqual(len(scans), 2)
        self.assertEqual(scans[0]["subnet"], "10.0.0.0/24")
        self.assertEqual(scans[1]["subnet"], "192.168.1.0/24")

    def test_scan_with_no_devices_is_saved(self):
        scan_id = history.save_scan(
            "192.168.1.0/24",
            []
        )

        scans = history.get_scan_history()
        saved_devices = history.get_scan_devices(scan_id)

        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0]["device_count"], 0)
        self.assertEqual(saved_devices, [])


if __name__ == "__main__":
    unittest.main()
