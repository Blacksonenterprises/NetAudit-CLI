# NetAudit CLI

**Mobile-Powered Local Network Vulnerability & Security Scanner**

NetAudit CLI is a Python-based network reconnaissance and security auditing tool designed for Termux and Linux. It helps users discover devices on authorized private networks, inspect TCP ports, identify exposed services, assess common security concerns, and generate structured security reports.

## Key Features

### 1. Network Discovery
- Discover reachable devices within an IPv4 subnet.
- Retrieve available IP addresses, hostnames, and MAC addresses.
- Use Nmap for network discovery.
- Validate private network ranges before scanning.

### 2. TCP Port Scanning
- Scan configurable TCP ports and port ranges.
- Identify port states and available service information.
- Retrieve service and version details where available.
- Validate scan targets and port ranges.

### 3. Network Analysis
- Summarize discovered network devices.
- Identify devices with missing hostnames.
- Detect duplicate MAC addresses.
- Flag invalid or out-of-subnet IP addresses.

### 4. Security Assessment
- Evaluate scan results using predefined security rules.
- Identify potentially risky exposed services.
- Categorize findings by severity.
- Display recommended remediation actions.

*Note: This is a rule-based preliminary security assessment, not a comprehensive vulnerability scanner or penetration-testing framework.*

### 5. Scan History
- Store network discovery results using SQLite.
- Retrieve previous discovery scans.
- Review saved device information.

### 6. Report Generation
- Generate JSON security reports.
- Generate HTML security reports.
- Include scan results and security assessment findings.
- Escape untrusted content in generated HTML reports.

### 7. Command-Line Interface
- Built with Python `argparse`.
- Uses Rich for organized terminal output.
- Provides separate commands for discovery, scanning, reporting, and history.

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core application logic |
| Nmap | Network discovery and TCP scanning |
| SQLite | Local scan history |
| Rich | Terminal interface |
| argparse | Command-line argument handling |
| JSON | Structured report output |
| HTML | Readable security reports |
| unittest | Automated testing |
| GitHub Actions | Continuous integration |

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
│   ├── test_cli.py
│   ├── test_database_history.py
│   ├── test_discovery.py
│   ├── test_network_analysis.py
│   ├── test_port_scanner.py
│   ├── test_report_generator.py
│   └── test_vulnerability_check.py
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

- Python 3.11 or later recommended (the CI workflow uses Python 3.11).
- Nmap installed and accessible from the system PATH.
- Git.
- Termux or a compatible Linux environment.

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
python -m pip install -r requirements.txt
```

## Usage

### Display application version

```bash
python main.py --version
```

### Display available commands

```bash
python main.py --help
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

NetAudit uses Python's built-in `unittest` framework.

Run the complete test suite locally:

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

Run a Python compilation check:

```bash
python -m compileall -q main.py modules database reports tests
```

### Continuous Integration

GitHub Actions automatically runs the following checks:

1. Checks out the repository.
2. Sets up Python 3.11.
3. Installs project dependencies.
4. Checks Python compilation.
5. Executes the automated unit tests.

The workflow runs on pushes and pull requests targeting the `main` branch and can also be triggered manually.

## Responsible Use

NetAudit CLI is intended for:

- Authorized network security auditing.
- Defensive cybersecurity assessments.
- Network administration and troubleshooting.
- Cybersecurity education and practical learning.

Only scan networks and devices you own or have explicit permission to assess.

Scan visibility and accuracy may vary depending on firewall rules, device isolation, operating-system permissions, and network configuration.

Security findings are preliminary indicators. The absence of findings does not guarantee that a system is secure, and a flagged service does not automatically prove that a vulnerability exists.

## Project Status

The project has an automated test suite and a GitHub Actions CI workflow. Live network operation should be validated separately in an authorized Termux or Linux environment.

## Author

**Blacksonenterprises**

GitHub: https://github.com/Blacksonenterprises

## License

This project is distributed under the MIT License. See the `LICENSE` file for details.
