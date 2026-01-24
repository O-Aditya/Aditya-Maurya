import os
import re
import datetime

# --- CONFIGURATION ---
BASE_DIR = "." 
OUTPUT_DIR = os.path.join(BASE_DIR, "Final_Forensic_Reports")
AUTHOR = "Aditya Maurya"

# Auto-detect log directory
LOG_DIR = None
for root, dirs, files in os.walk(BASE_DIR):
    if "raw_logs" in dirs:
        LOG_DIR = os.path.join(root, "raw_logs")
        break
    if "raw_file" in dirs:
        LOG_DIR = os.path.join(root, "raw_file")
        break

if not LOG_DIR:
    LOG_DIR = BASE_DIR # Fallback

os.makedirs(OUTPUT_DIR, exist_ok=True)

# --- 🧠 EXPANDED KNOWLEDGE BASE (30+ Artifacts) ---
# Maps specific keywords in filenames to Forensic Definitions
ARTIFACT_KB = {
    # --- SYSTEM INFORMATION ---
    "bios": {"cat": "System Info", "title": "BIOS & Firmware Configuration", "risk": "Outdated firmware can harbor vulnerabilities."},
    "systeminfo": {"cat": "System Info", "title": "System Information Summary", "risk": "Reveals OS version and patch level gaps."},
    "os_summary": {"cat": "System Info", "title": "OS Summary", "risk": "OS version details for vulnerability mapping."},
    "hotfixes": {"cat": "Patch Management", "title": "Installed Hotfixes", "risk": "Missing critical security patches."},
    "volumes": {"cat": "Disk Forensics", "title": "Disk Volumes & Storage", "risk": "Hidden partitions may store stolen data."},
    "bitlocker": {"cat": "Disk Encryption", "title": "BitLocker Status", "risk": "Unencrypted drives allow physical data theft."},
    "transcript": {"cat": "Forensic Metadata", "title": "Collection Transcript", "risk": "Audit trail of the collection process."},
    
    # --- NETWORK FORENSICS ---
    "ipconfig": {"cat": "Network Config", "title": "IP Configuration", "risk": "Rogue DNS or unusual subnets."},
    "netstat": {"cat": "Network Telemetry", "title": "Netstat Connections", "risk": "Active C2 connections or listening backdoors."},
    "active_connections": {"cat": "Network Telemetry", "title": "Active Network Connections", "risk": "Unauthorized remote access tools (AnyDesk/TeamViewer)."},
    "dns_cache": {"cat": "Network Forensics", "title": "DNS Cache Analysis", "risk": "Evidence of visiting phishing or C2 domains."},
    "arp": {"cat": "Network Forensics", "title": "ARP Cache", "risk": "Static entries may indicate ARP poisoning."},
    "route": {"cat": "Network Forensics", "title": "Routing Table", "risk": "Malicious route redirection."},
    "hosts": {"cat": "Network Forensics", "title": "Hosts File Analysis", "risk": "Redirection of legitimate sites to malicious IPs."},
    "smb_shares": {"cat": "Network Shares", "title": "SMB Shares", "risk": "Open shares allow lateral movement."},
    "wifi": {"cat": "Wireless Forensics", "title": "Wi-Fi Profiles", "risk": "Connecting to rogue APs or leaking credentials."},
    "firewall": {"cat": "Network Security", "title": "Firewall Configuration", "risk": "Disabled firewall or permissive rules."},
    
    # --- IDENTITY & ACCESS ---
    "local_admins": {"cat": "Identity", "title": "Local Administrators", "risk": "Unauthorized users with full system control."},
    "local_users": {"cat": "Identity", "title": "Local User Accounts", "risk": "Hidden or backdoor user accounts."},
    "cmdkey": {"cat": "Credential Theft", "title": "Stored Credentials (CmdKey)", "risk": "Saved passwords accessible to attackers."},
    "failed_logins": {"cat": "Auth Logs", "title": "Failed Login Attempts", "risk": "Brute force attack indicators."},
    "successful_logins": {"cat": "Auth Logs", "title": "Successful Interactive Logins", "risk": "Unauthorized physical or RDP access."},
    
    # --- PERSISTENCE & EXECUTION ---
    "scheduled_tasks": {"cat": "Persistence", "title": "Scheduled Tasks", "risk": "Malware persisting across reboots."},
    "services": {"cat": "Persistence", "title": "System Services", "risk": "Backdoor services running as SYSTEM."},
    "startup": {"cat": "Persistence", "title": "Startup Items", "risk": "Programs launching automatically at login."},
    "registry_run": {"cat": "Persistence", "title": "Registry Run Keys", "risk": "Fileless persistence mechanisms."},
    "wmi": {"cat": "Advanced Persistence", "title": "WMI Event Filters/Consumers", "risk": "Sophisticated fileless malware persistence."},
    
    # --- RISK SIGNALS & THREATS ---
    "usb_disks": {"cat": "Device Forensics", "title": "USB Device History", "risk": "Data exfiltration via USB or malware entry."},
    "rdp": {"cat": "Remote Access", "title": "RDP Connection Logs", "risk": "Lateral movement via Remote Desktop."},
    "powershell": {"cat": "Script Forensics", "title": "PowerShell Activity", "risk": "Malicious scripts or 'Fileless' attacks."},
    "prefetch": {"cat": "Execution Artifacts", "title": "Prefetch Listing", "risk": "Evidence of program execution history."},
    "print_jobs": {"cat": "Data Loss", "title": "Print Job History", "risk": "Sensitive documents printed (Data Exfiltration)."},
    "recent_documents": {"cat": "User Activity", "title": "Recent Documents", "risk": "Access to sensitive files."},
    "process_creation": {"cat": "Process Forensics", "title": "Process Creation Audit", "risk": "Malware execution chains."},
    
    # --- BROWSER & SOFTWARE ---
    "extensions": {"cat": "Browser Forensics", "title": "Browser Extensions", "risk": "Malicious extensions stealing data."},
    "installed_software": {"cat": "Asset Mgmt", "title": "Installed Software", "risk": "Vulnerable or unauthorized software."},
    "defender": {"cat": "Endpoint Security", "title": "Defender Status", "risk": "AV disabled or tampering detected."},
    "edr": {"cat": "Endpoint Security", "title": "EDR Candidates", "risk": "Presence or absence of security sensors."},
    "errors": {"cat": "System Health", "title": "Error Logs", "risk": "System instability caused by malware."}
}

# --- 🕵️ ANALYSIS ENGINE ---

def analyze_content(filepath, keyword):
    """Scans for red flags based on file type."""
    suspicious = []
    
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
            lower_content = content.lower()
            
            # Universal Checks
            if "mimikatz" in lower_content: suspicious.append("Artifact 'Mimikatz' detected (Credential Dumping).")
            if "psexec" in lower_content: suspicious.append("Artifact 'PsExec' detected (Lateral Movement).")
            if "anydesk" in lower_content: suspicious.append("Remote Access Tool 'AnyDesk' detected.")
            if "teamviewer" in lower_content: suspicious.append("Remote Access Tool 'TeamViewer' detected.")

            # Specific Checks
            if "wifi" in keyword and "password" in lower_content:
                suspicious.append("Cleartext Wi-Fi password potentially visible.")
            if "defender" in keyword and "false" in lower_content:
                suspicious.append("Security protection appears DISABLED.")
            if "bitlocker" in keyword and "off" in lower_content:
                suspicious.append("Disk encryption is OFF.")
            if "usb" in keyword and "sandisk" in lower_content:
                suspicious.append("External USB storage activity detected.")
            if "rdp" in keyword and len(content.splitlines()) > 5:
                suspicious.append("High volume of RDP connections detected.")
            if "failed" in keyword and len(content.splitlines()) > 10:
                suspicious.append("High volume of failed login attempts (Brute Force Indicator).")

    except:
        pass # Skip binary read errors
        
    return suspicious

# --- 📝 REPORT WRITER ---

def generate_report(filename, filepath, keyword):
    kb = ARTIFACT_KB[keyword]
    suspicious = analyze_content(filepath, keyword)
    
    md = []
    md.append(f"# {kb['title']}")
    md.append(f"**Category:** {kb['cat']}")
    md.append(f"**File Name:** `{filename}`")
    md.append(f"**Date:** {datetime.datetime.now().strftime('%Y-%m-%d')}\n")

    md.append("## 1. Artifact Overview")
    md.append(f"**Purpose:** Analyzes {filename} to understand system state relating to {kb['cat']}.")
    md.append(f"**Security Relevance:** {kb['risk']}")
    
    md.append("\n## 2. Findings & Analysis")
    if suspicious:
        md.append("| 🚨 Risk Level | Finding | Implication |")
        md.append("| :--- | :--- | :--- |")
        for s in suspicious:
            md.append(f"| **HIGH** | {s} | Potential security breach or policy violation. |")
    else:
        md.append("✅ No high-risk anomalies detected in this specific artifact.")
        md.append("\n_Note: Absence of evidence is not evidence of absence. Correlate with other logs._")

    md.append("\n## 3. Recommendations")
    if suspicious:
        md.append("- **Investigate:** Validate the suspicious findings immediately.")
        md.append("- **Contain:** If confirmed malicious, isolate the system.")
    else:
        md.append("- **Monitor:** Continue standard logging and monitoring.")
        md.append("- **Retain:** Archive log for compliance.")

    md.append("\n---\n")
    md.append(f"Report prepared by {AUTHOR}")
    
    return "\n".join(md)

# --- 🚀 MAIN EXECUTION ---

def main():
    print(f"🚀 Starting Deep Forensic Analysis in: {LOG_DIR}")
    count = 0

    # Walk through ALL directories (including subfolders)
    for root, dirs, files in os.walk(LOG_DIR):
        for file in files:
            # Skip script and hidden files
            if file.endswith(".py") or file.startswith("."): continue
            
            fname_lower = file.lower()
            matched_key = None
            
            # Find matching definition in KB
            for key in ARTIFACT_KB.keys():
                if key in fname_lower:
                    matched_key = key
                    break
            
            if matched_key:
                count += 1
                # Calculate relative path for cleaner logging
                rel_path = os.path.relpath(os.path.join(root, file), LOG_DIR)
                print(f"   -> Analyzing: {rel_path}...")
                
                report_content = generate_report(file, os.path.join(root, file), matched_key)
                
                # Save Report (sanitize filename)
                safe_name = f"Report_{file.replace('.', '_')}.md"
                with open(os.path.join(OUTPUT_DIR, safe_name), "w", encoding="utf-8") as f:
                    f.write(report_content)

    if count == 0:
        print("❌ No recognizable log files found.")
    else:
        print(f"✅ Generated {count} Forensic Reports in '{OUTPUT_DIR}'")

if __name__ == "__main__":
    main()