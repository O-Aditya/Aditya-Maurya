# Cybersecurity Log Analysis Assignment

## Objective
Systematic analysis of system, network, and database logs to identify security threats and misconfigurations. This project involves examining various log sources including browser history, system logs, and network activity logs to detect vulnerabilities.

## Tools Used
* grep (Pattern Matching)
* strings (Binary Analysis)
* Automation Scripts
* Network Analysis Utilities

## Key Findings

### Critical Security Risks
* **Credential Leakage (AWS Keys)**: Found AWS Access Key IDs exposed in browser history files. This is a severe configuration error leading to potential cloud compromise.
* **Wi-Fi Security**: Wi-Fi profiles were found containing cleartext passwords for multiple networks (e.g., `Kanan WIFi`, `AndroidAP_5013`, `Galaxy A23 CDAC`).

### High & Medium Risks
* **SQL Injection Suspects**: Detected suspicious usage of `SELECT` statements in PowerShell operational logs (`powershell_operational_filtered.csv`), attempting to query WMI objects with dynamic naming, resembling injection patterns.
* **Remote Access Tools**: **AnyDesk** is active and listening on ports `7070` and `49672`. Unmanaged remote access tools present a persistence and data exfiltration risk.
* **Authentication Failures**: Evidence of multiple failed login attempts (Event ID 4625) detected in system logs (`failed_logins.csv`).

## Documentation
For detailed breakdowns of these findings, please refer to the full reports:
* [System & Credential Analysis Report](docs/Analysis_Report.md)
* [Network Analysis Report](docs/Network_Analysis_Report.md)
