# NetAudit CLI

**Mobile-Powered Local Network Vulnerability & Security Scanner**

NetAudit CLI is a Python-based network reconnaissance and security assessment tool designed to identify devices, analyze exposed network services, evaluate common security weaknesses, and generate structured security reports.

Built with Python, Nmap, Scapy, Bash, and SQLite, NetAudit provides a lightweight command-line solution for local network auditing. It is designed to operate on Android devices through Termux and on Linux systems.

---

## Project Overview

Understanding what is connected to a network and identifying potentially exposed services are essential aspects of network security.

NetAudit CLI simplifies this process by combining network discovery, port analysis, service identification, security checks, and reporting capabilities into one command-line application.

The tool provides users with a structured approach to examining authorized private networks, reviewing scan history, and documenting security observations.

## Key Features

### 1. Network Discovery
- Identifies active devices on a local IPv4 network.
- Performs subnet discovery and network mapping.
- Extracts available IP addresses, MAC addresses, and hostnames.
- Identifies reachable devices using Nmap.

### 2. Port Scanning
- Performs TCP port scanning.
- Identifies open, closed, and filtered ports.
- Supports configurable port ranges.
- Highlights potentially exposed network services.

### 3. Service and Version Detection
- Identifies services running on discovered open ports.
- Retrieves available service and version information.
- Helps identify outdated or potentially vulnerable services.

### 4. Security Assessment
- Performs basic security baseline checks.
- Identifies potentially risky exposed services.
- Flags common network misconfigurations and security concerns.
- Provides findings to support further investigation.

### 5. Scan History Management
- Uses SQLite for local scan-data storage.
- Records scan dates, target subnets, and discovered devices.
- Maintains historical scan information.
- Supports retrieval and review of previous scan results.

### 6. Security Report Generation
- Generates structured JSON reports.
- Produces HTML security reports.
- Organizes discovery results, port information, and security findings.
- Provides readable records for documentation and review.

### 7. Command-Line Interface
- Provides a structured CLI using Python argparse and Rich.
- Supports modular commands for different assessment operations.
- Displays scan results in organized terminal tables.
- Designed for lightweight operation on mobile and desktop environments.

---

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core application and scanning logic |
| Nmap | Network discovery, port scanning, service detection |
| Scapy | Packet manipulation and network analysis |
| Bash | Supporting scripts and automation |
| SQLite | Local database and scan history |
| Rich | Terminal interface and formatted output |
| argparse | Command-line argument handling |
| XML | Nmap result processing |
| JSON | Structured security reports |
| HTML | Readable security reports |

## Project Architecture

```text
NetAudit-CLI/
│
├── main.py
├── config.py
├── requirements.txt
│
├── modules/
│   ├── __init__.py
│   ├── discovery.py
│   ├── port_scanner.py
│   ├── service_detection.py
│   ├── vulnerability_check.py
│   └── network_analysis.py
│
├── database/
│   ├── __init__.py
│   └── history.py
│
├── reports/
│   ├── json/
│   └── html/
│
├── scripts/
│   ├── setup.sh
│   └── run_audit.sh
│
├── tests/
│
├── .gitignore
├── LICENSE
└── README.md
```

## Installation

### Requirements

- Python 3.9 or later
- Nmap
- Git
- Termux on Android or a Linux environment
- Appropriate permissions for the selected network assessment operations

### 1. Clone the repository

```bash
git clone https://github.com/Blacksonenterprises/NetAudit-CLI.git
cd NetAudit-CLI
```

### 2. Install system dependencies

**Termux:**

```bash
pkg update && pkg upgrade -y
pkg install python nmap git -y
```

**Ubuntu/Debian:**

```bash
sudo apt update
sudo apt install python3 python3-pip nmap git -y
```

### 3. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 4. Launch NetAudit

```bash
python main.py
```

Display the application version:

```bash
python main.py --version
```

## Usage Examples

The following examples illustrate the intended command interface.

### Discover network devices

```bash
python main.py discover --subnet 192.168.1.0/24
```

### Scan a target's ports

```bash
python main.py scan --target 192.168.1.10 --ports 1-1000
```

### Generate a JSON report

```bash
python main.py report --format json
```

### Generate an HTML report

```bash
python main.py report --format html
```

### Review previous scans

```bash
python main.py history
```

Replace example IP addresses and subnets with targets you are authorized to assess. Command availability depends on the installed application version.

---

## Security and Responsible Use

NetAudit CLI is intended for:

- Authorized local network auditing.
- Defensive cybersecurity assessments.
- Network administration and troubleshooting.
- Cybersecurity education and practical learning.
- Identifying potentially exposed services and security weaknesses.

**Important:** Only scan networks and devices you own or have explicit permission to assess. Do not use this tool to access, disrupt, or test third-party networks without authorization.

Network visibility and scan accuracy may vary depending on firewall rules, device isolation, operating-system permissions, and network configuration.

## Platform Compatibility

| Platform | Support |
|---|---|
| Android | Termux |
| Linux | Ubuntu, Debian and compatible distributions |

Some network operations may require additional privileges or platform-specific configuration.

## Project Goals

NetAudit CLI was designed around three core objectives:

1. **Accessibility:** Make local network auditing possible from lightweight environments, including Android devices.
2. **Visibility:** Help users understand which devices and services are present on an authorized network.
3. **Documentation:** Maintain scan records and produce structured reports that support security review.

## Future Enhancements

Potential areas for further improvement include:

- More comprehensive vulnerability detection.
- Advanced network traffic analysis.
- Scheduled and automated security audits.
- Enhanced reporting and visualization.
- Improved cross-platform compatibility.

## Author

**Blacksonenterprises**

GitHub: [Blacksonenterprises](https://github.com/Blacksonenterprises)

## License

This project is distributed under the MIT License. See the [LICENSE](LICENSE) file for details.
