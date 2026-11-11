
"""
NetAudit CLI - Report Generator

Generates JSON and HTML reports from network
scan results and security assessment findings.
"""

import json
import html

from datetime import datetime
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

JSON_DIR = BASE_DIR / "json"
HTML_DIR = BASE_DIR / "html"


def prepare_report_directories():
    """Create report output directories when necessary."""

    JSON_DIR.mkdir(parents=True, exist_ok=True)
    HTML_DIR.mkdir(parents=True, exist_ok=True)


def build_report_data(target, ports, scan_results, findings):
    """Build a structured report containing scan information."""

    severity_summary = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }

    for finding in findings:
        severity = finding.get("severity", "").lower()

        if severity in severity_summary:
            severity_summary[severity] += 1

    open_ports = [
        result for result in scan_results
        if result.get("state") == "open"
    ]

    return {
        "application": "NetAudit CLI",
        "report_version": "1.0",
        "generated_at": datetime.now().astimezone().isoformat(),
        "target": target,
        "port_range": ports,
        "scan_summary": {
            "total_ports_identified": len(scan_results),
            "open_ports": len(open_ports),
            "security_findings": len(findings)
        },
        "severity_summary": severity_summary,
        "port_results": scan_results,
        "security_findings": findings
    }


def generate_json_report(report_data):
    """Generate and save a JSON security report."""

    prepare_report_directories()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    filename = (
        f"netaudit_report_{timestamp}.json"
    )

    report_path = JSON_DIR / filename

    with report_path.open("w", encoding="utf-8") as file:
        json.dump(
            report_data,
            file,
            indent=4,
            ensure_ascii=False
        )

    return report_path


def generate_html_report(report_data):
    """Generate and save an HTML security report."""

    prepare_report_directories()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    filename = (
        f"netaudit_report_{timestamp}.html"
    )

    report_path = HTML_DIR / filename

    summary = report_data["scan_summary"]
    severity = report_data["severity_summary"]

    port_rows = []

    for item in report_data["port_results"]:

        product_version = " ".join(
            value for value in (
                item.get("product", ""),
                item.get("version", "")
            ) if value
        )

        port_rows.append(
            "<tr>"
            f"<td>{html.escape(str(item.get('port', '')))}</td>"
            f"<td>{html.escape(str(item.get('protocol', '')))}</td>"
            f"<td>{html.escape(str(item.get('state', '')))}</td>"
            f"<td>{html.escape(str(item.get('service', '')))}</td>"
            f"<td>{html.escape(product_version or 'Unknown')}</td>"
            "</tr>"
        )

    finding_rows = []

    for finding in report_data["security_findings"]:

        finding_rows.append(
            "<tr>"
            f"<td>{html.escape(str(finding.get('port', '')))}</td>"
            f"<td>{html.escape(str(finding.get('service', '')))}</td>"
            f"<td>{html.escape(str(finding.get('severity', '')))}</td>"
            f"<td>{html.escape(str(finding.get('finding', '')))}</td>"
            f"<td>{html.escape(str(finding.get('recommendation', '')))}</td>"
            "</tr>"
        )

    port_content = "\n".join(port_rows) or (
        '<tr><td colspan="5">No port information available.</td></tr>'
    )

    finding_content = "\n".join(finding_rows) or (
        '<tr><td colspan="5">No flagged security findings.</td></tr>'
    )

    target = html.escape(str(report_data["target"]))
    generated_at = html.escape(str(report_data["generated_at"]))
    port_range = html.escape(str(report_data["port_range"]))

    document = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetAudit Security Report</title>

<style>
body {{
    font-family: Arial, sans-serif;
    background: #f3f4f6;
    color: #1f2937;
    margin: 0;
    padding: 25px;
}}

.container {{
    max-width: 1100px;
    margin: auto;
    background: white;
    padding: 30px;
    border-radius: 10px;
}}

h1 {{
    color: #0f172a;
}}

h2 {{
    color: #1d4ed8;
    margin-top: 35px;
}}

.subtitle {{
    color: #64748b;
}}

.cards {{
    display: flex;
    flex-wrap: wrap;
    gap: 15px;
    margin: 25px 0;
}}

.card {{
    flex: 1;
    min-width: 150px;
    background: #eff6ff;
    padding: 18px;
    border-radius: 8px;
}}

.card strong {{
    display: block;
    font-size: 25px;
    margin-top: 8px;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 15px;
}}

th, td {{
    border: 1px solid #e5e7eb;
    padding: 11px;
    text-align: left;
    overflow-wrap: anywhere;
}}

th {{
    background: #1e3a8a;
    color: white;
}}

tr:nth-child(even) {{
    background: #f8fafc;
}}

footer {{
    margin-top: 35px;
    padding-top: 15px;
    border-top: 1px solid #e5e7eb;
    color: #64748b;
    font-size: 13px;
}}

@media print {{
    body {{
        background: white;
        padding: 0;
    }}

    .container {{
        box-shadow: none;
    }}
}}
</style>
</head>

<body>
<div class="container">

<h1>NetAudit CLI</h1>

<p class="subtitle">
Local Network Security Assessment Report
</p>

<h2>Assessment Information</h2>

<p><strong>Target:</strong> {target}</p>
<p><strong>Port Range:</strong> {port_range}</p>
<p><strong>Generated:</strong> {generated_at}</p>

<h2>Scan Summary</h2>

<div class="cards">
    <div class="card">
        Identified Ports
        <strong>{summary['total_ports_identified']}</strong>
    </div>

    <div class="card">
        Open Ports
        <strong>{summary['open_ports']}</strong>
    </div>

    <div class="card">
        Security Findings
        <strong>{summary['security_findings']}</strong>
    </div>
</div>

<h2>Severity Summary</h2>

<table>
<tr><th>Severity</th><th>Count</th></tr>
<tr><td>Critical</td><td>{severity['critical']}</td></tr>
<tr><td>High</td><td>{severity['high']}</td></tr>
<tr><td>Medium</td><td>{severity['medium']}</td></tr>
<tr><td>Low</td><td>{severity['low']}</td></tr>
<tr><td>Informational</td><td>{severity['info']}</td></tr>
</table>

<h2>Port Scan Results</h2>

<table>
<tr>
<th>Port</th>
<th>Protocol</th>
<th>State</th>
<th>Service</th>
<th>Product / Version</th>
</tr>
{port_content}
</table>

<h2>Security Findings and Recommendations</h2>

<table>
<tr>
<th>Port</th>
<th>Service</th>
<th>Severity</th>
<th>Finding</th>
<th>Recommendation</th>
</tr>
{finding_content}
</table>

<footer>
Generated by NetAudit CLI.
For authorized network security assessment only.
</footer>

</div>
</body>
</html>
"""

    report_path.write_text(
        document,
        encoding="utf-8"
    )

    return report_path


def generate_report(
    target,
    ports,
    scan_results,
    findings,
    report_format="json"
):
    """Generate a JSON or HTML security report."""

    report_data = build_report_data(
        target,
        ports,
        scan_results,
        findings
    )

    if report_format == "json":
        return generate_json_report(report_data)

    if report_format == "html":
        return generate_html_report(report_data)

    raise ValueError(
        "Unsupported report format. Choose json or html."
    )
