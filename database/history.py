
"""
NetAudit CLI - Database History Module

Stores network discovery scans and discovered devices
using SQLite.
"""

import sqlite3
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_PATH = BASE_DIR / "database" / "netaudit.db"


def get_connection():
    """Create a connection to the NetAudit database."""

    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    """Create database tables if they do not exist."""

    with get_connection() as connection:

        connection.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subnet TEXT NOT NULL,
                scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                device_count INTEGER NOT NULL
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                ip TEXT NOT NULL,
                hostname TEXT,
                mac TEXT,
                status TEXT,
                FOREIGN KEY (scan_id)
                    REFERENCES scans(id)
                    ON DELETE CASCADE
            )
        """)

        connection.commit()


def save_scan(subnet, devices):
    """Save a discovery scan and its discovered devices."""

    initialize_database()

    with get_connection() as connection:

        cursor = connection.execute(
            """
            INSERT INTO scans (subnet, device_count)
            VALUES (?, ?)
            """,
            (subnet, len(devices))
        )

        scan_id = cursor.lastrowid

        for device in devices:

            connection.execute(
                """
                INSERT INTO devices (
                    scan_id, ip, hostname, mac, status
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    device.get("ip"),
                    device.get("hostname"),
                    device.get("mac"),
                    device.get("status")
                )
            )

        connection.commit()

    return scan_id


def get_scan_history():
    """Retrieve previous network discovery scans."""

    initialize_database()

    with get_connection() as connection:

        cursor = connection.execute(
            """
            SELECT id, subnet, scan_date, device_count
            FROM scans
            ORDER BY id DESC
            """
        )

        return [dict(row) for row in cursor.fetchall()]


def get_scan_devices(scan_id):
    """Retrieve devices belonging to a particular scan."""

    initialize_database()

    with get_connection() as connection:

        cursor = connection.execute(
            """
            SELECT ip, hostname, mac, status
            FROM devices
            WHERE scan_id = ?
            ORDER BY ip
            """,
            (scan_id,)
        )

        return [dict(row) for row in cursor.fetchall()]
