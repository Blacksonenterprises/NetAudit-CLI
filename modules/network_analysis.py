
"""
NetAudit CLI - Network Analysis Module

Analyzes discovered network devices and produces
a structured summary of the network inventory.
"""

import ipaddress
from collections import Counter


def analyze_network_devices(devices, subnet):
    """
    Analyze discovered devices within a specified subnet.

    Args:
        devices (list): Discovered network device records.
        subnet (str): IPv4 network in CIDR notation.

    Returns:
        dict: Network analysis summary.
    """

    try:
        network = ipaddress.ip_network(subnet, strict=False)

    except ValueError as error:
        raise ValueError(f"Invalid subnet: {error}")

    if network.version != 4:
        raise ValueError("Only IPv4 networks are supported.")

    if not isinstance(devices, list):
        raise ValueError("Devices must be provided as a list.")

    valid_devices = []
    invalid_ips = []

    for device in devices:
        if not isinstance(device, dict):
            continue

        ip_address = device.get("ip")

        try:
            address = ipaddress.ip_address(ip_address)

            if address.version != 4 or address not in network:
                invalid_ips.append(str(ip_address))
                continue

        except (ValueError, TypeError):
            invalid_ips.append(str(ip_address))
            continue

        valid_devices.append(device)

    mac_addresses = [
        device.get("mac", "").strip().lower()
        for device in valid_devices
        if device.get("mac")
        and device.get("mac").strip().lower() not in (
            "unknown",
            "unavailable",
            "none"
        )
    ]

    mac_counts = Counter(mac_addresses)

    duplicate_macs = [
        mac for mac, count in mac_counts.items()
        if count > 1
    ]

    missing_hostnames = [
        device.get("ip")
        for device in valid_devices
        if not device.get("hostname")
        or device.get("hostname").lower() in (
            "unknown",
            "none"
        )
    ]

    active_devices = [
        device for device in valid_devices
        if device.get("status", "").lower()
        in ("up", "online", "active")
    ]

    return {
        "network": str(network),
        "network_address": str(network.network_address),
        "broadcast_address": str(network.broadcast_address),
        "total_discovered": len(devices),
        "valid_devices": len(valid_devices),
        "active_devices": len(active_devices),
        "invalid_or_outside_ips": invalid_ips,
        "missing_hostnames": missing_hostnames,
        "duplicate_mac_addresses": duplicate_macs,
        "devices": valid_devices
    }
