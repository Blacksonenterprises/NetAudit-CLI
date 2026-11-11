
"""
NetAudit CLI - TCP Port Scanner

Performs TCP connect scans against authorized private IPv4 targets.
Uses Nmap to identify port states and available service information.
"""

import ipaddress
import subprocess
import xml.etree.ElementTree as ET


def validate_target(target):
    """Validate an individual private IPv4 target."""

    try:
        address = ipaddress.ip_address(target)

        if address.version != 4:
            raise ValueError("Only IPv4 targets are supported.")

        if not address.is_private:
            raise ValueError("Only private IPv4 targets are allowed.")

        return str(address)

    except ValueError as error:
        raise ValueError(f"Invalid target: {error}")


def validate_ports(ports):
    """Validate a port number or port range."""

    try:
        parts = ports.split("-")

        if len(parts) == 1:
            start = end = int(parts[0])
        elif len(parts) == 2:
            start, end = map(int, parts)
        else:
            raise ValueError

        if not (1 <= start <= end <= 65535):
            raise ValueError

        if end - start > 9999:
            raise ValueError("Maximum scan range is 10,000 ports.")

        return f"{start}-{end}" if start != end else str(start)

    except ValueError:
        raise ValueError(
            "Invalid port range. Use a port such as 443 or a range such as 1-1000."
        )


def scan_ports(target, ports="1-1000"):
    """Perform a TCP connect scan and return structured results."""

    target = validate_target(target)
    ports = validate_ports(ports)

    command = [
        "nmap",
        "-sT",
        "-sV",
        "-p",
        ports,
        "-oX",
        "-",
        target
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=300
        )

        if result.returncode != 0:
            raise RuntimeError(
                result.stderr.strip() or "Nmap port scan failed."
            )

        root = ET.fromstring(result.stdout)
        host = root.find("host")

        if host is None:
            return []

        scan_results = []

        for port in host.findall("./ports/port"):
            state_element = port.find("state")
            service_element = port.find("service")

            state = (
                state_element.get("state")
                if state_element is not None
                else "unknown"
            )

            service = (
                service_element.get("name")
                if service_element is not None
                else "unknown"
            )

            product = (
                service_element.get("product")
                if service_element is not None
                else ""
            )

            version = (
                service_element.get("version")
                if service_element is not None
                else ""
            )

            scan_results.append({
                "port": int(port.get("portid")),
                "protocol": port.get("protocol", "tcp"),
                "state": state,
                "service": service,
                "product": product,
                "version": version
            })

        return scan_results

    except FileNotFoundError:
        raise RuntimeError("Nmap is not installed or not in PATH.")

    except subprocess.TimeoutExpired:
        raise RuntimeError("Port scan timed out.")

    except ET.ParseError:
        raise RuntimeError("Could not interpret Nmap scan results.")
