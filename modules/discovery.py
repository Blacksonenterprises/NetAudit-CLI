
"""
NetAudit CLI - Network Discovery Module

Uses Nmap to identify reachable devices
on an authorized private IPv4 network.
"""

import ipaddress
import subprocess
import xml.etree.ElementTree as ET


def validate_subnet(subnet):
    """Validate and restrict the target to private IPv4 networks."""

    try:
        network = ipaddress.ip_network(subnet, strict=False)

        if network.version != 4:
            raise ValueError("Only IPv4 networks are supported.")

        if not network.is_private:
            raise ValueError("Only private IPv4 networks are allowed.")

        if network.num_addresses > 256:
            raise ValueError(
                "Network too large. Maximum: 256 addresses."
            )

        return network

    except ValueError as error:
        raise ValueError(f"Invalid subnet: {error}")


def discover_devices(subnet):
    """Discover reachable devices using Nmap."""

    network = validate_subnet(subnet)

    command = [
        "nmap",
        "-sn",
        "-oX",
        "-",
        str(network)
    ]

    print(f"\n[*] Discovering devices on {network}...")

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=180
        )

        if result.returncode != 0:
            raise RuntimeError(
                result.stderr.strip() or "Nmap scan failed."
            )

        root = ET.fromstring(result.stdout)

        devices = []

        for host in root.findall("host"):

            status = host.find("status")

            if status is None or status.get("state") != "up":
                continue

            device = {
                "ip": None,
                "mac": None,
                "hostname": None,
                "status": "up"
            }

            for address in host.findall("address"):

                address_type = address.get("addrtype")

                if address_type == "ipv4":
                    device["ip"] = address.get("addr")

                elif address_type == "mac":
                    device["mac"] = address.get("addr")

            hostname = host.find("./hostnames/hostname")

            if hostname is not None:
                device["hostname"] = hostname.get("name")

            if device["ip"]:
                devices.append(device)

        return devices

    except FileNotFoundError:
        raise RuntimeError(
            "Nmap is not installed or not in PATH."
        )

    except subprocess.TimeoutExpired:
        raise RuntimeError(
            "Network discovery timed out."
        )

    except ET.ParseError:
        raise RuntimeError(
            "Could not interpret Nmap scan results."
        )
