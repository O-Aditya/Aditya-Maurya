# Installed Software Analysis Report
**Folder Name:** raw_logs
**File Types:** CSV
**Collection Date:** 2026-01-25
**Report Generated:** 2026-01-25

## 1. File Overview and Meaning
### 1.1 What Is the Installed Software File?
This artifact is a complete inventory of applications installed on the host, typically gathered from the Windows Registry Uninstall keys.

### 1.2 Purpose and Importance
Software inventories are used to detect unauthorized software (Shadow IT), vulnerable applications, and remote access tools (RATs) often used by attackers.

### 1.3 File Format and Structure
The file is a Comma-Separated Values (CSV) list containing application names, versions, publishers, and installation dates.

## 2. Data Types and Structure
### 2.1 Key Attributes or Fields
* DisplayName
* DisplayVersion
* Publisher
* InstallDate

### 2.2 Field Descriptions
| Field Name | Data Type | Description |
| :--- | :--- | :--- |
| DisplayName | String | The name of the application as it appears in Add/Remove Programs. |
| Publisher | String | The vendor who signed or created the software. |

### 2.3 Sensitive or Security-Relevant Data Categories
* **Risk Signals:** Presence of hacking tools, RATs, or outdated software.

## 3. Where This Data Is Used
### 3.1 Security Operations Use Cases
Vulnerability management teams use this to map CVEs (Common Vulnerabilities and Exposures) to installed versions.

### 3.2 Incident Response and Threat Hunting
Hunters scan this list for "dual-use" tools like AnyDesk, TeamViewer, or Nmap which may indicate an intruder is maintaining access.

### 3.3 Correlation With Other Artifacts
* **Process Creation Logs:** To see if the installed software is actually running.
* **Network Connections:** To see if the software is communicating externally.

## 4. Data Protection and Security Precautions
### 4.1 Why This Data Is Sensitive
It provides a roadmap for attackers to identify vulnerable software to exploit (e.g., an old version of Adobe Reader).

### 4.2 Storage, Access Control, and Handling
* **Access Control:** Standard log access restrictions.

### 4.3 Retention and Disposal Considerations
Update continuously; historical retention helps track when a malicious tool was first installed.

## 5. Sample Findings and Anomalies
### 5.1 Normal or Expected Findings
* Standard business applications (Office, Edge, Teams).
* Security agents (Sophos, Defender).

### 5.2 Suspicious or High-Risk Findings (ANALYSIS OF PROVIDED LOG)
| Finding | Security Implication |
| :--- | :--- |
| **AnyDesk (Version 9.0.9)** | **High Risk:** Remote Access Tool (RAT) detected. Often used by attackers for persistence and data exfiltration. Requires immediate validation of authorization. |
| **Python 3.13.1 & VS Code** | **Context:** Indicates this is a developer workstation or an admin machine, which are high-value targets. |

## 6. Executive Summary
**Data Sensitivity Level:** Medium
**Protection Required:** Access Control
**Forensic Value:** Very High