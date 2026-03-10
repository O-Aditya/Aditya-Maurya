"""Parsers for software, admins, credentials, and hotfixes."""
import csv
import io
import re
from typing import Dict, List
from datetime import datetime, timedelta
from ..models import Finding


def _parse_csv(content: str) -> List[dict]:
    if not content or not content.strip():
        return []
    try:
        return list(csv.DictReader(io.StringIO(content)))
    except Exception:
        return []


# Software patterns to flag
RISKY_SOFTWARE = {
    "remote_access": {
        "patterns": ["anydesk", "teamviewer", "ultraviewer", "rustdesk", "ammyy",
                      "supremo", "logmein", "splashtop", "connectwise", "bomgar",
                      "vnc", "tightvnc", "realvnc", "radmin"],
        "severity": "HIGH",
        "desc": "Remote access tool — can be used for unauthorized remote control",
        "remediation": "Uninstall if not authorized: Get-WmiObject Win32_Product | Where-Object {{$_.Name -like '*{name}*'}} | ForEach-Object {{$_.Uninstall()}}",
    },
    "hacking_tools": {
        "patterns": ["mimikatz", "nmap", "wireshark", "metasploit", "cobalt", "burp",
                      "john the ripper", "hashcat", "hydra", "cain", "aircrack",
                      "sqlmap", "nessus", "openvas"],
        "severity": "CRITICAL",
        "desc": "Security/hacking tool — should not be on production endpoints",
        "remediation": "Remove immediately: wmic product where \"name like '%{name}%'\" call uninstall",
    },
    "activation_tools": {
        "patterns": ["aact", "kms", "kmspico", "activator", "crack", "patch",
                      "keygen", "loader", "toolkit"],
        "severity": "CRITICAL",
        "desc": "Software activation/piracy tool — indicates unauthorized software use and likely contains malware",
        "remediation": "Remove immediately and scan system: Start-MpScan -ScanType FullScan",
    },
    "p2p_torrent": {
        "patterns": ["utorrent", "bittorrent", "qbittorrent", "transmission",
                      "vuze", "deluge", "limewire"],
        "severity": "MEDIUM",
        "desc": "Peer-to-peer/torrent client — data exfiltration risk and potentially pirated content",
        "remediation": "Uninstall if not authorized",
    },
    "outdated_browsers": {
        "patterns": ["internet explorer"],
        "severity": "MEDIUM",
        "desc": "Outdated browser — known vulnerabilities",
        "remediation": "Uninstall and use a modern browser",
    },
}


def parse_software(files: Dict[str, str]) -> tuple:
    """Parse installed_software.csv for risky software."""
    findings = []
    software_list = []
    content = files.get("installed_software.csv", "")
    if not content:
        return software_list, findings

    rows = _parse_csv(content)
    flagged = set()

    for row in rows:
        name = row.get("Name", row.get('"Name"', "")).strip().strip('"')
        version = row.get("Version", row.get('"Version"', "")).strip().strip('"')
        publisher = row.get("Publisher", row.get('"Publisher"', row.get("Vendor", ""))).strip().strip('"')
        install_date = row.get("InstallDate", row.get('"InstallDate"', "")).strip().strip('"')

        if not name:
            continue

        software_list.append({
            "name": name, "version": version,
            "publisher": publisher, "install_date": install_date
        })

        name_lower = name.lower()
        for category, info in RISKY_SOFTWARE.items():
            for pattern in info["patterns"]:
                if pattern in name_lower and name_lower not in flagged:
                    flagged.add(name_lower)
                    findings.append(Finding(
                        severity=info["severity"], category="Software",
                        title=f"Risky software: {name} ({category.replace('_', ' ')})",
                        description=f"{info['desc']}. Software: {name} v{version}. Publisher: {publisher}.",
                        remediation=info["remediation"].format(name=name),
                        owner="IT Security",
                        attacker_context=f"Found {category.replace('_', ' ')} tool '{name}' — I can use this for my attack.",
                        source_files=["installed_software.csv"],
                    ))
                    break

    return software_list, findings


def parse_local_admins(files: Dict[str, str]) -> tuple:
    """Parse local_admins.csv."""
    findings = []
    admins = []
    content = files.get("local_admins.csv", "")
    if not content:
        return admins, findings

    rows = _parse_csv(content)
    for row in rows:
        name = row.get("Name", row.get('"Name"', "")).strip().strip('"')
        sid = row.get("SID", row.get('"SID"', "")).strip().strip('"')
        obj_class = row.get("ObjectClass", row.get('"ObjectClass"', "")).strip().strip('"')
        if name:
            admins.append({"name": name, "sid": sid, "class": obj_class})

    # Flag excessive admins (more than 2)
    if len(admins) > 2:
        admin_names = ", ".join(a["name"] for a in admins)
        findings.append(Finding(
            severity="HIGH", category="Access Control",
            title=f"Excessive local administrators ({len(admins)})",
            description=f"Machine has {len(admins)} local admin accounts: {admin_names}. Principle of least privilege violated.",
            remediation=f'Remove-LocalGroupMember -Group "Administrators" -Member "<username>"',
            owner="IT Security",
            attacker_context="Multiple admin accounts = multiple targets for credential theft. Each one gives me full control.",
            source_files=["local_admins.csv"],
        ))

    # Check for suspicious admin names
    suspicious_names = ["test", "temp", "admin1", "backdoor", "guest", "default", "user1"]
    for admin in admins:
        if any(sus in admin["name"].lower() for sus in suspicious_names):
            findings.append(Finding(
                severity="HIGH", category="Access Control",
                title=f"Suspicious admin account: {admin['name']}",
                description=f"Account '{admin['name']}' has local admin rights and has a suspicious name pattern.",
                remediation=f'Remove-LocalGroupMember -Group "Administrators" -Member "{admin["name"]}"',
                owner="IT Security",
                attacker_context="This looks like a backdoor account. Easy target for takeover.",
                source_files=["local_admins.csv"],
            ))

    return admins, findings


def parse_credentials(files: Dict[str, str]) -> tuple:
    """Parse cmdkey_list.txt."""
    findings = []
    creds = []
    content = files.get("cmdkey_list.txt", "")
    if not content:
        return creds, findings

    current_target = ""
    current_type = ""
    current_user = ""

    for line in content.splitlines():
        line_stripped = line.strip()
        if line_stripped.startswith("Target:"):
            if current_target:
                creds.append({"target": current_target, "type": current_type, "user": current_user})
            current_target = line_stripped.split(":", 1)[1].strip()
            current_type = ""
            current_user = ""
        elif line_stripped.startswith("Type:"):
            current_type = line_stripped.split(":", 1)[1].strip()
        elif line_stripped.startswith("User:"):
            current_user = line_stripped.split(":", 1)[1].strip()

    if current_target:
        creds.append({"target": current_target, "type": current_type, "user": current_user})

    if creds:
        # Check for domain credentials
        domain_creds = [c for c in creds if "domain" in c["target"].lower() or "\\" in c.get("user", "")]
        if domain_creds:
            targets = ", ".join(c["target"] for c in domain_creds[:3])
            findings.append(Finding(
                severity="HIGH", category="Credential Storage",
                title=f"Stored domain credentials ({len(domain_creds)})",
                description=f"Domain credentials stored in Credential Manager: {targets}. These can be extracted by attackers.",
                remediation="cmdkey /delete:<target>",
                owner="IT Security",
                attacker_context="Stored domain creds = I can extract them with mimikatz and move laterally to other machines.",
                source_files=["cmdkey_list.txt"],
            ))
        elif len(creds) > 0:
            findings.append(Finding(
                severity="MEDIUM", category="Credential Storage",
                title=f"{len(creds)} stored credential(s) in Credential Manager",
                description=f"Credential Manager has {len(creds)} stored entries. Review for necessity.",
                remediation="cmdkey /list",
                owner="IT Security",
                source_files=["cmdkey_list.txt"],
            ))

    return creds, findings


def parse_hotfixes(files: Dict[str, str], collection_date: str = "") -> tuple:
    """Parse installed_hotfixes.txt (PowerShell table format)."""
    findings = []
    hotfixes = []
    content = files.get("installed_hotfixes.txt", "")
    if not content:
        findings.append(Finding(
            severity="MEDIUM", category="Patching",
            title="Hotfix status unknown",
            description="installed_hotfixes.txt was not collected. Cannot assess patch status.",
            remediation="Get-HotFix | Sort-Object InstalledOn -Descending | Select -First 10",
            owner="IT",
            source_files=["installed_hotfixes.txt"],
        ))
        return hotfixes, "", -1, findings

    lines = [l for l in content.splitlines() if l.strip() and not l.strip().startswith("-")]
    if len(lines) < 2:
        return hotfixes, "", -1, findings

    # Parse header + data rows
    header = lines[0]
    # Find column positions from header
    for line in lines[1:]:
        parts = line.split()
        if len(parts) >= 3:
            kb = parts[0].strip() if parts[0].strip().startswith("KB") else ""
            if not kb:
                for p in parts:
                    if p.strip().startswith("KB"):
                        kb = p.strip()
                        break
            desc = ""
            date_str = ""
            for p in parts:
                # Try to find date
                if re.match(r'\d{1,2}/\d{1,2}/\d{4}', p):
                    date_str = p
                elif p in ["Update", "Security", "Hotfix"]:
                    desc = p

            if kb:
                hotfixes.append({"kb": kb, "description": desc, "date": date_str})

    # Calculate patch gap
    last_patch_date = ""
    patch_gap_days = -1
    if hotfixes:
        dates = []
        for hf in hotfixes:
            try:
                d = datetime.strptime(hf["date"], "%m/%d/%Y")
                dates.append(d)
            except (ValueError, TypeError):
                pass
        if dates:
            latest = max(dates)
            last_patch_date = latest.strftime("%Y-%m-%d")

            # Calculate gap
            if collection_date:
                try:
                    coll_date = datetime.strptime(collection_date[:10], "%Y-%m-%d")
                except ValueError:
                    try:
                        coll_date = datetime.strptime(collection_date[:10], "%m/%d/%Y")
                    except ValueError:
                        coll_date = datetime.now()
            else:
                coll_date = datetime.now()

            patch_gap_days = (coll_date - latest).days

            if patch_gap_days > 90:
                findings.append(Finding(
                    severity="CRITICAL", category="Patching",
                    title=f"System {patch_gap_days} days behind on patches",
                    description=f"Last patch installed on {last_patch_date}. System is {patch_gap_days} days behind. Critical vulnerabilities likely unpatched.",
                    remediation="Install-WindowsUpdate -AcceptAll -AutoReboot",
                    owner="IT",
                    attacker_context=f"{patch_gap_days} days unpatched = known exploits available. I would check CVE databases for this OS version.",
                    source_files=["installed_hotfixes.txt"],
                ))
            elif patch_gap_days > 30:
                findings.append(Finding(
                    severity="HIGH", category="Patching",
                    title=f"System {patch_gap_days} days behind on patches",
                    description=f"Last patch installed {last_patch_date}. Recommended patching cycle: <30 days.",
                    remediation="Install-WindowsUpdate -AcceptAll",
                    owner="IT",
                    source_files=["installed_hotfixes.txt"],
                ))

    return hotfixes, last_patch_date, patch_gap_days, findings


def parse_local_users(files: Dict[str, str]) -> List[Finding]:
    """Parse local_users_passwordinfo.csv for password policy issues."""
    findings = []
    content = files.get("local_users_passwordinfo.csv", "")
    if not content:
        return findings

    rows = _parse_csv(content)
    for row in rows:
        name = row.get("Name", row.get('"Name"', "")).strip().strip('"')
        enabled = row.get("Enabled", row.get('"Enabled"', "")).strip().strip('"').lower()
        pw_set = row.get("PasswordLastSet", row.get('"PasswordLastSet"', "")).strip().strip('"')
        pw_expires = row.get("PasswordExpires", row.get('"PasswordExpires"', "")).strip().strip('"')
        pw_never_expires = row.get("PasswordNeverExpires", row.get('"PasswordNeverExpires"', "")).strip().strip('"').lower()

        if enabled != "true":
            continue

        if pw_never_expires == "true":
            findings.append(Finding(
                severity="MEDIUM", category="Access Control",
                title=f"Password never expires: {name}",
                description=f"Account '{name}' has PasswordNeverExpires=True. This violates password rotation policies.",
                remediation=f'Set-LocalUser -Name "{name}" -PasswordNeverExpires $false',
                owner="IT Security",
                source_files=["local_users_passwordinfo.csv"],
            ))

    return findings
