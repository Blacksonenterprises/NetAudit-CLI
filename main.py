
#!/usr/bin/env python3

"""
NetAudit CLI
Mobile-Powered Local Network Security Scanner
Version: 1.1.0
"""

import argparse

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.align import Align

from modules.discovery import discover_devices
from database.history import (
    save_scan,
    get_scan_history,
    get_scan_devices
)

console = Console()
VERSION = "1.1.0"


def display_banner():
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
    console.print("[bold green]Application:[/bold green] NetAudit CLI")
    console.print(f"[bold green]Version:[/bold green] {VERSION}")
    console.print("[bold green]Platform:[/bold green] Termux / Linux")
    console.print("[bold green]Status:[/bold green] [yellow]Development[/yellow]")
    console.print()


def create_parser():
    parser = argparse.ArgumentParser(
        prog="netaudit",
        description="NetAudit - Local Network Security Scanner"
    )

    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"NetAudit CLI {VERSION}"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        help="Available commands"
    )

    discover = subparsers.add_parser(
        "discover",
        help="Discover active devices on an authorized network"
    )
    discover.add_argument(
        "--subnet",
        required=True,
        help="Target subnet, e.g. 192.168.1.0/24"
    )

    scan = subparsers.add_parser(
        "scan",
        help="Scan ports on an authorized target"
    )
    scan.add_argument("--target", required=True)
    scan.add_argument("--ports", default="1-1000")

    report = subparsers.add_parser(
        "report",
        help="Generate security reports"
    )
    report.add_argument(
        "--format",
        choices=["json", "html"],
        default="json"
    )

    subparsers.add_parser(
        "history",
        help="View previous scan records"
    )

    return parser


def show_discovered_devices(devices):
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
        f"\n[bold green]Total devices found: "
        f"{len(devices)}[/bold green]"
    )


def run_discovery(subnet):
    try:
        devices = discover_devices(subnet)
        scan_id = save_scan(subnet, devices)

        console.print(
            f"\n[bold green]Scan saved successfully! "
            f"Scan ID: {scan_id}[/bold green]"
        )

        show_discovered_devices(devices)

    except (ValueError, RuntimeError) as error:
        console.print(f"[bold red]Error: {error}[/bold red]")


def show_history():
    try:
        scans = get_scan_history()

        if not scans:
            console.print("[yellow]No previous scans found.[/yellow]")
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
            devices = get_scan_devices(record["id"])

            if devices:
                device_table = Table(
                    title=f"Devices in Scan #{record['id']}"
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
        console.print(f"[bold red]History error: {error}[/bold red]")


def main():
    parser = create_parser()
    args = parser.parse_args()

    display_banner()
    display_status()

    if args.command == "discover":
        run_discovery(args.subnet)

    elif args.command == "scan":
        console.print(
            "[yellow]Port scanning module is under development.[/yellow]"
        )
        console.print(f"Target: {args.target}")
        console.print(f"Ports: {args.ports}")

    elif args.command == "report":
        console.print(
            "[yellow]Report generator is under development.[/yellow]"
        )
        console.print(f"Format: {args.format}")

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
