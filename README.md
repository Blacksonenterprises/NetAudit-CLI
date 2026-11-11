# NetAudit CLI

**Mobile-Powered Local Network Vulnerability & Security Scanner**

NetAudit CLI is a Python-based network reconnaissance and security auditing tool designed for Termux and Linux. It helps users discover devices on authorized private networks, inspect TCP ports, identify exposed services, assess common security concerns, and generate structured reports.

## Key Features

### 1. Network Discovery
- Discover reachable devices within an IPv4 subnet.
- Retrieve available IP addresses, hostnames, and MAC addresses.
- Use Nmap for network discovery.

### 2. TCP Port Scanning
- Scan configurable TCP port ranges.
- Identify port states and available service information.
- Review potentially exposed network services.

### 3. Network Analysis
- Summarize discovered network devices.
- Identify devices with missing hostnames.
- Detect duplicate MAC addresses.
- Flag invalid or out-of-subnet IP addresses.

### 4. Security Assessment
- Evaluate scan results against basic security checks.
- Categorize identified findings by severity.
- Display recommended remediation actions.

### 5. Scan History
- Store network discovery results using SQLite.
- Retrieve previous discovery scans.
- Review saved device information.

### 6. Report Generation
- Generate JSON security reports.
- Generate HTML security reports.
- Include scan results and security assessment findings.

### 7. Command-Line Interface
- Built with Python `argparse`.
- Uses Rich for organized terminal output.
- Provides separate commands for discovery, scanning, reporting, and history.

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core application logic |
| Nmap | Network discovery and scanning |
| SQLite | Local scan history |
| Rich | Terminal interface |
| argparse | Command-line argument handling |
| JSON | Structured report output |
| HTML | Readable security reports |
| GitHub Actions | Automated testing |

## Project Structure

```text
NetAudit-CLI/
│
├── main.py
├── requirements.txt
│
├── modules/
│   ├── __init__.py
│   ├── discovery.py
│   ├── port_scanner.py
│   ├── vulnerability_check.py
│   └── network_analysis.py
│
├── database/
│   ├── __init__.py
│   └── history.py
│
├── reports/
│   └── report_generator.py
│
├── tests/
│   └── test_network_analysis.py
│
├── .github/
│   └── workflows/
│       └── tests.yml
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
- Termux or a compatible Linux environment

### 1. Clone the repository

```bash
git clone https://github.com/Blacksonenterprises/NetAudit-CLI.git
cd NetAudit-CLI
```

### 2. Install system dependencies

**Termux**

```bash
pkg update && pkg upgrade -y
pkg install python nmap git -y
```

**Ubuntu/Debian**

```bash
sudo apt update
sudo apt install python3 python3-pip nmap git -y
```

### 3. Install Python dependencies

```bash
pip install -r requirements.txt
```

## Usage

### Display application version

```bash
python main.py --version
```

### Discover network devices

```bash
python main.py discover --subnet 192.168.1.0/24
```

### Scan TCP ports

```bash
python main.py scan --target 192.168.1.10 --ports 1-1000
```

### Generate a JSON report

```bash
python main.py report --target 192.168.1.10 --ports 1-1000 --format json
```

### Generate an HTML report

```bash
python main.py report --target 192.168.1.10 --ports 1-1000 --format html
```

### View previous discovery scans

```bash
python main.py history
```

Replace example IP addresses and subnets with targets you own or are explicitly authorized to assess.

## Automated Testing

NetAudit uses Python's `unittest` framework for automated tests.

Run the test suite locally:

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

GitHub Actions is configured to execute the automated tests when changes are pushed to the main branch or a pull request is opened.

## Responsible Use

NetAudit CLI is intended for:
- Authorized network security auditing.
- Defensive cybersecurity assessments.
- Network administration and troubleshooting.
- Cybersecurity education and practical learning.

Only scan networks and devices you own or have explicit permission to assess.

Scan visibility and accuracy may vary depending on firewall rules, device isolation, operating-system permissions, and network configuration.

Security findings are preliminary indicators and should not be treated as proof that a system is vulnerable or secure.

## Author

**Blacksonenterprises**

GitHub: https://github.com/Blacksonenterprises

## License

This project is distributed under the MIT License. See the `LICENSE` file for details.
