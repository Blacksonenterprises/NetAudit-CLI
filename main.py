
#!/usr/bin/env python3

"""
NetAudit CLI
Mobile-Powered Local Network Vulnerability & Security Scanner

Version: 1.2.0
Platform: Termux / Linux
"""

import argparse

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.align import Align

from modules.discovery import discover_devices
from modules.port_scanner import scan_ports

from database.history import (
    save_scan,
    get_scan_history,
    get_scan_devices
)


console = Console()

VERSION = "1.2.0"


def display_banner():
    """Display the application banner."""

    banner = Text()
    banner.append("NET", style="bold cyan")
    banner.append("AUDIT", style="bold white")
    banner.append(" CLI", style="bold red")

    subtitle = Text(
        "LOCAL NETWORK SECURITY & RECONNAISSANCE TOOL",
        style="bold green"
    )

    content = Text.assemble(banner, "\n", subtitle)

    console.print()
    console.print(
        Panel(
            Align.center(content),
            border_style="cyan",
            padding=(1, 2)
        )
    )


def display_status():
    """Display application information."""

    console.print(
        "[bold green]Application:[/bold green] NetAudit CLI"
    )
    console.print(
        f"[bold green]Version:[/bold green] {VERSION}"
    )
    console.print(
        "[bold green]Platform:[/bold green] Termux / Linux"
    )
    console.print(
        "[bold green]Status:[/bold green] [yellow]Active Development[/yellow]"
    )
    console.print()


def create_parser():
    """Configure command-line arguments."""

    parser = argparse.ArgumentParser(
        prog="netaudit",
        description="NetAudit - Local Network Security Scanner"
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"NetAudit CLI {VERSION}"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        help="Available commands"
    )

    discover = subparsers.add_parser(
        "discover",
        help="Discover devices on an authorized private network"
    )

    discover.add_argument(
        "--subnet",
        required=True,
        help="Target subnet, e.g. 192.168.1.0/24"
    )

    scan = subparsers.add_parser(
        "scan",
        help="Perform TCP port and service scanning"
    )

    scan.add_argument(
        "--target",
        required=True,
        help="Authorized private IPv4 target"
    )

    scan.add_argument(
        "--ports",
        default="1-1000",
        help="Port or port range (default: 1-1000)"
    )

    report = subparsers.add_parser(
        "report",
        help="Generate security reports"
    )

    report.add_argument(
        "--format",
        choices=["json", "html"],
        default="json",
        help="Report format"
    )

    subparsers.add_parser(
        "history",
        help="View previous discovery scans"
    )

    return parser


def show_discovered_devices(devices):
    """Display discovered devices in a table."""

    if not devices:
        console.print(
            "[yellow]No reachable devices were discovered.[/yellow]"
        )
        return

    table = Table(title="NetAudit - Discovered Devices")

    table.add_column("IP Address", style="cyan")
    table.add_column("Hostname", style="green")
    table.add_column("MAC Address", style="yellow")
    table.add_column("Status", style="bold green")

    for device in devices:
        table.add_row(
            device.get("ip") or "Unknown",
            device.get("hostname") or "Unknown",
            device.get("mac") or "Unavailable",
            (device.get("status") or "Unknown").upper()
        )

    console.print(table)

    console.print(
        f"\n[bold green]Total devices found: {len(devices)}[/bold green]"
    )


def show_port_results(results):
    """Display TCP port scan results."""

    if not results:
        console.print(
            "[yellow]No port information was returned.[/yellow]"
        )
        return

    table = Table(title="NetAudit - TCP Port Scan Results")

    table.add_column("Port", style="cyan")
    table.add_column("Protocol", style="white")
    table.add_column("State", style="bold green")
    table.add_column("Service", style="yellow")
    table.add_column("Product / Version", style="magenta")

    for item in results:
        product_version = " ".join(
            part for part in (
                item.get("product"),
                item.get("version")
            ) if part
        )

        state = item.get("state", "unknown")

        state_style = (
            "bold green" if state == "open"
            else "yellow" if state == "filtered"
            else "red"
        )

        table.add_row(
            str(item.get("port", "Unknown")),
            item.get("protocol", "tcp").upper(),
            f"[{state_style}]{state.upper()}[/{state_style}]",
            item.get("service", "unknown"),
            product_version or "Unknown"
        )

    console.print(table)

    open_ports = sum(
        1 for item in results
        if item.get("state") == "open"
    )

    console.print(
        f"\n[bold green]Ports identified: {len(results)}[/bold green]"
    )
    console.print(
        f"[bold cyan]Open ports: {open_ports}[/bold cyan]"
    )


def run_discovery(subnet):
    """Discover devices and save discovery results."""

    try:
        devices = discover_devices(subnet)

        scan_id = save_scan(subnet, devices)

        console.print(
            f"\n[bold green]Discovery saved! Scan ID: {scan_id}[/bold green]"
        )

        show_discovered_devices(devices)

    except (ValueError, RuntimeError) as error:
        console.print(
            f"[bold red]Discovery error: {error}[/bold red]"
        )


def run_port_scan(target, ports):
    """Run TCP port scanning against an authorized target."""

    try:
        console.print(
            f"\n[cyan]Starting TCP scan against {target}...[/cyan]"
        )

        results = scan_ports(target, ports)

        show_port_results(results)

    except (ValueError, RuntimeError) as error:
        console.print(
            f"[bold red]Port scan error: {error}[/bold red]"
        )


def show_history():
    """Display previous discovery scans and their devices."""

    try:
        scans = get_scan_history()

        if not scans:
            console.print(
                "[yellow]No previous scans found.[/yellow]"
            )
            return

        table = Table(title="NetAudit - Scan History")

        table.add_column("Scan ID", style="cyan")
        table.add_column("Subnet", style="green")
        table.add_column("Date", style="white")
        table.add_column("Devices Found", style="yellow")

        for record in scans:
            table.add_row(
                str(record["id"]),
                record["subnet"],
                str(record["scan_date"]),
                str(record["device_count"])
            )

        console.print(table)

        for record in scans:
            scan_id = record["id"]
            devices = get_scan_devices(scan_id)

            if not devices:
                continue

            device_table = Table(
                title=f"Devices in Scan #{scan_id}"
            )

            device_table.add_column("IP Address", style="cyan")
            device_table.add_column("Hostname", style="green")
            device_table.add_column("MAC Address", style="yellow")
            device_table.add_column("Status", style="bold green")

            for device in devices:
                device_table.add_row(
                    device["ip"] or "Unknown",
                    device["hostname"] or "Unknown",
                    device["mac"] or "Unavailable",
                    (device["status"] or "Unknown").upper()
                )

            console.print(device_table)

    except Exception as error:
        console.print(
            f"[bold red]History error: {error}[/bold red]"
        )


def main():
    """Application entry point."""

    parser = create_parser()
    args = parser.parse_args()

    display_banner()
    display_status()

    if args.command == "discover":
        run_discovery(args.subnet)

    elif args.command == "scan":
        run_port_scan(args.target, args.ports)

    elif args.command == "report":
        console.print(
            "[yellow]Report generation module is not connected yet.[/yellow]"
        )
        console.print(f"Requested format: {args.format}")

    elif args.command == "history":
        show_history()

    else:
        parser.print_help()


if __name__ == "__main__":

    try:
        main()

    except KeyboardInterrupt:
        console.print(
            "\n[bold red]Operation cancelled.[/bold red]"
        )
