# Local Users Password Info Analysis Report
**Folder Name:** raw_logs
**File Types:** CSV
**Collection Date:** 2026-01-25
**Report Generated:** 2026-01-25

## 1. File Overview and Meaning
### 1.1 What Is the Local Users Password Info File?
This file provides metadata about local user accounts, specifically focusing on their status (Enabled/Disabled) and the timestamp of when their password was last changed.

### 1.2 Purpose and Importance
It is used to audit password hygiene. Stale passwords (unchanged for >90 days) are easier to crack. It also helps identify dormant accounts that should be disabled to reduce the attack surface.

### 1.3 File Format and Structure
The file is a Comma-Separated Values (CSV) list with columns for Name, Enabled, and PasswordLastSet.

## 2. Data Types and Structure
### 2.1 Key Attributes or Fields
* Name
* Enabled (True/False)
* PasswordLastSet (DateTime)

### 2.2 Field Descriptions
| Field Name | Data Type | Description |
| :--- | :--- | :--- |
| PasswordLastSet | DateTime | The exact time the password hash was last updated. |
| Enabled | Boolean | Whether the account can be used for login. |

### 2.3 Sensitive or Security-Relevant Data Categories
* **Account Hygiene:** Identifies weak links in authentication policy.

## 3. Where This Data Is Used
### 3.1 Security Operations Use Cases
Used for compliance reporting (e.g., PCI-DSS requires 90-day rotation).

### 3.2 Incident Response and Threat Hunting
IR teams look for accounts enabled recently or passwords changed outside of business hours.

### 3.3 Correlation With Other Artifacts
* **Local Admins:** To see if the stale account is also an administrator.
* **Successful Logins:** To see if the dormant account is actively being used.

## 4. Data Protection and Security Precautions
### 4.1 Why This Data Is Sensitive
Reveals which accounts are valid targets. Knowing an account is "Enabled" with an old password invites brute-force attacks.

### 4.2 Storage, Access Control, and Handling
* **Access Control:** Standard log access.

### 4.3 Retention and Disposal Considerations
Retain as proof of policy enforcement.

## 5. Sample Findings and Anomalies
### 5.1 Normal or Expected Findings
* Built-in `Guest` and `Administrator` should be `False` (Disabled).
* Active users should have `PasswordLastSet` within the last 90 days.

### 5.2 Suspicious or High-Risk Findings (ANALYSIS OF PROVIDED LOG)
| Finding | Security Implication |
| :--- | :--- |
| **User 'Dell': PasswordLastSet 12-10-2024** | **Policy Violation:** The password for this admin user is over 1 year old (relative to the Oct 2025 collection date). This significantly increases the risk of credential compromise. |
| **Administrator: Enabled=False** | Normal: The built-in administrator account is correctly disabled. |
| **WsiAccount: Enabled=False** | Normal: Service accounts are disabled, reducing the attack surface. |

## 6. Executive Summary
**Data Sensitivity Level:** Medium
**Protection Required:** Access Control
**Forensic Value:** High