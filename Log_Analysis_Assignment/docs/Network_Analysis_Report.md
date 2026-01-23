# Network Analysis Report

## 1. Executive Summary
This report details the findings from the analysis of the `network_analysis` log data. The analysis covers active network connections, DNS cache, Wi-Fi profiles, SMB shares, and the system hosts file. Key findings include the presence of remote access software (AnyDesk) and critical security risks involving cleartext Wi-Fi passwords stored in the system.

## 2. Active Connections Analysis
**Source File:** `raw_logs/network_analysis/active_connections.csv`

The system has several listening ports and established connections. notable observations include:

- **Remote Access Tools**: 
  - **AnyDesk** is running and listening on ports `7070` and `49672`. 
  - Connection established to `148.113.16.46` (AnyDesk) on port `443`.
  - *Risk*: Remote access tools can be used by attackers for persistence or data exfiltration. Ensure this is authorized.

- **Web Traffic**: 
  - Multiple established connections to Microsoft/Azure IPs (`52.x.x.x`, `20.x.x.x`) on port `443` (HTTPS), associated with `OneDrive`, `OfficeClickToRun`, and system services.
  - Connection to `WhatsApp` (`163.70.143.61`) on port `5222`.
  - Connection to `Chrome` (`172.217.194.188`) on port `5228`.

- **Listening Services**:
  - `spoolsv` (Print Spooler) listening on `49668`.
  - `ChatGPT` application listening on localhost `56250`.

## 3. Wi-Fi Profile Security (CRITICAL)
**Source File:** `raw_logs/network_analysis/wifi_profiles.csv`

**CRITICAL SECURITY FINDING**: Wi-Fi profiles contain cleartext passwords (key material). This is a significant security risk.

| Profile Name | Security Type | Key Content (Password) |
|--------------|---------------|------------------------|
| **KANAN WIFi** | WPA2-Personal | `Kipl@1996` |
| **AndroidAP_5013** | WPA3-Personal | `12346789` |
| **Galaxy A23 CDAC** | WPA3-Personal | `Kanan2025` |

*Recommendation*: Rotate these credentials immediately and ensure reports/logs do not expose sensitive credentials in cleartext.

## 4. DNS Cache Analysis
**Source File:** `raw_logs/network_analysis/dns_cache.csv`

The DNS cache shows resolution for typical user applications:
- **Microsoft/OneDrive**: `onedrive.live.com`, `graph.microsoft.com`, `login.live.com`, `blob.core.windows.net`.
- **Google services**: `accounts.google.com`, `tunnel.googlezip.net`.
- **WonderPush**: `measurements-api.wonderpush.com` (Push notification service).
- **Anomalous Entry**: A failed or empty resolution for `"deskofskycrawle"` (Line 30). This could be a typo or an artifact of a specific application probe.

## 5. SMB Shares Analysis
**Source File:** `raw_logs/network_analysis/smb_shares.csv`

The system has standard administrative shares enabled:
- `ADMIN$`, `C$`, `D$` (Default administrative shares).
- `IPC$` (Remote IPC).
- `print$` (Printer Drivers).
- **Shared Printer**: `MIS printer` (HP LaserJet Tank 1020).

No unusual user-created file shares were observed visible to `Everyone`, but administrative shares are standard targets for lateral movement if credentials are compromised.

## 6. Hosts File Analysis
**Source File:** `raw_logs/network_analysis/hosts_file.txt`

The `hosts` file is standard and unmodified. It contains only the default comments and example entries. No malicious redirections were found.
