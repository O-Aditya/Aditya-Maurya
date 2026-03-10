"""Parsers for network information: firewall, ARP, connections, shares."""
import csv
import io
import re
from typing import Dict, List
from ..models import Finding, NetworkInfo


def _parse_csv(content: str) -> List[dict]:
    if not content or not content.strip():
        return []
    try:
        return list(csv.DictReader(io.StringIO(content)))
    except Exception:
        return []


# Dangerous ports to flag when open
RISKY_PORTS = {
    21: "FTP", 23: "Telnet", 135: "WMI/RPC", 139: "NetBIOS",
    445: "SMB", 1433: "MSSQL", 1434: "MSSQL Browser",
    3306: "MySQL", 3389: "RDP", 4444: "Meterpreter default",
    5800: "VNC HTTP", 5900: "VNC", 5938: "TeamViewer",
    5985: "WinRM HTTP", 5986: "WinRM HTTPS",
    7070: "AnyDesk", 8080: "HTTP Proxy", 8443: "Alt HTTPS",
}


def parse_firewall_profiles(files: Dict[str, str]) -> tuple:
    """Parse firewall_profiles.txt (PowerShell table)."""
    findings = []
    profiles = {"domain": None, "private": None, "public": None}

    content = files.get("firewall_profiles.txt", "")
    if not content:
        findings.append(Finding(
            severity="MEDIUM", category="Firewall",
            title="Firewall status unknown",
            description="firewall_profiles.txt was not collected.",
            remediation="Get-NetFirewallProfile | Select Profile, Enabled",
            owner="IT Security",
            source_files=["firewall_profiles.txt"],
        ))
        return profiles, findings

    for line in content.splitlines():
        line_lower = line.lower().strip()
        if not line_lower:
            continue

        # Match profile lines in table format
        # "Domain   True" or "Domain   Enabled   NotConfigured"
        parts = line.split()
        if len(parts) >= 2:
            profile = parts[0].lower()
            if profile in profiles:
                enabled = any(v.lower() in ["true", "enabled", "on"] for v in parts[1:])
                profiles[profile] = enabled

    # Check for disabled profiles
    for profile_name, enabled in profiles.items():
        if enabled is False:
            findings.append(Finding(
                severity="HIGH", category="Firewall",
                title=f"Firewall {profile_name.title()} profile is DISABLED",
                description=f"The {profile_name} firewall profile is disabled. Machine is exposed to network attacks.",
                remediation=f"Set-NetFirewallProfile -Profile {profile_name.title()} -Enabled True",
                owner="IT Security",
                attacker_context=f"Disabled {profile_name} firewall = I can freely connect to any port on this machine.",
                source_files=["firewall_profiles.txt"],
            ))

    return profiles, findings


def parse_firewall_rules(files: Dict[str, str]) -> tuple:
    """Parse firewall_rules.csv for risky inbound rules."""
    findings = []
    risky_rules = []
    content = files.get("firewall_rules.csv", "")
    if not content:
        return risky_rules, findings

    rows = _parse_csv(content)
    for row in rows:
        direction = row.get("Direction", "").strip().strip('"').lower()
        action = row.get("Action", "").strip().strip('"').lower()
        enabled = row.get("Enabled", "").strip().strip('"').lower()
        local_port = row.get("LocalPort", row.get("LocalPorts", "")).strip().strip('"')
        remote_addr = row.get("RemoteAddress", row.get("RemoteAddresses", "")).strip().strip('"')
        name = row.get("DisplayName", row.get("Name", "")).strip().strip('"')

        # Only care about enabled inbound allow rules
        if direction not in ["inbound", "in"] or action not in ["allow", "accept"]:
            continue
        if enabled not in ["true", "yes", "1", ""]:
            continue

        # Check if it allows any remote address on risky ports
        if remote_addr.lower() in ["any", "*", "0.0.0.0/0", "localsubnet,any"]:
            ports = []
            for part in local_port.replace(",", " ").split():
                try:
                    p = int(part.strip())
                    if p in RISKY_PORTS:
                        ports.append(p)
                except ValueError:
                    if part.lower() == "any":
                        ports = list(RISKY_PORTS.keys())[:3]
                        break

            for port in ports:
                rule_info = {"name": name, "port": port, "service": RISKY_PORTS.get(port, "Unknown")}
                risky_rules.append(rule_info)
                sev = "CRITICAL" if port in [3389, 445, 5900, 4444] else "HIGH"
                findings.append(Finding(
                    severity=sev, category="Firewall",
                    title=f"Firewall allows inbound {RISKY_PORTS.get(port, '')} (port {port}) from ANY",
                    description=f"Rule '{name}' allows inbound connections to port {port} ({RISKY_PORTS.get(port, 'Unknown')}) from any source. This exposes the machine to network-based attacks.",
                    remediation=f'Disable-NetFirewallRule -DisplayName "{name}"',
                    owner="IT Security",
                    attacker_context=f"Port {port} is open to the world. I would scan for this and exploit it remotely.",
                    source_files=["firewall_rules.csv"],
                ))

    return risky_rules, findings


def parse_arp_table(files: Dict[str, str], local_subnet: str = "") -> tuple:
    """Parse arp_a.txt for unusual entries."""
    findings = []
    entries = []
    content = files.get("arp_a.txt", "")
    if not content:
        return entries, findings

    for line in content.splitlines():
        # Match ARP entries: "  192.168.29.1         xx-xx-xx-xx-xx-xx     dynamic"
        match = re.match(r'\s+([\d.]+)\s+([\w-]+)\s+(\w+)', line)
        if match:
            ip, mac, entry_type = match.group(1), match.group(2), match.group(3)
            if ip.startswith("224.") or ip.startswith("239.") or ip == "255.255.255.255":
                continue  # Skip multicast/broadcast
            entries.append({"ip": ip, "mac": mac, "type": entry_type})

    # Flag if unusually many ARP entries (>50 unique IPs = suspicious)
    unique_ips = set(e["ip"] for e in entries)
    if len(unique_ips) > 50:
        findings.append(Finding(
            severity="MEDIUM", category="Network",
            title=f"Large ARP table: {len(unique_ips)} unique IPs",
            description=f"ARP table contains {len(unique_ips)} unique IPs. Possible network scanning or unusual communication patterns.",
            remediation="arp -a | findstr dynamic",
            owner="IT Security",
            attacker_context="Lots of ARP entries could mean someone scanned the network from this machine.",
            source_files=["arp_a.txt"],
        ))

    return entries, findings


def parse_active_connections(files: Dict[str, str]) -> tuple:
    """Parse network_analysis/active_connections.csv or netstat_ano.txt."""
    findings = []
    suspicious = []
    content = files.get("network_analysis/active_connections.csv",
                        files.get("netstat_ano.txt", ""))
    if not content:
        return suspicious, findings

    open_risky = {}  # port -> count

    if "," in content.split("\n")[0]:
        # CSV format
        rows = _parse_csv(content)
        for row in rows:
            local_addr = row.get("LocalAddress", row.get("Local Address", "")).strip().strip('"')
            local_port = row.get("LocalPort", "").strip().strip('"')
            state = row.get("State", "").strip().strip('"').lower()
            pid = row.get("OwningProcess", row.get("PID", "")).strip().strip('"')

            if state in ["listening", "listen", "established"]:
                try:
                    port = int(local_port)
                    if port in RISKY_PORTS:
                        open_risky[port] = open_risky.get(port, 0) + 1
                except (ValueError, TypeError):
                    pass
    else:
        # netstat -ano text format
        for line in content.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0].upper() in ["TCP", "UDP"]:
                local = parts[1]
                state = parts[3] if len(parts) > 3 else parts[2]
                if ":" in local:
                    try:
                        port = int(local.rsplit(":", 1)[1])
                        if port in RISKY_PORTS and state.upper() in ["LISTENING", "ESTABLISHED"]:
                            open_risky[port] = open_risky.get(port, 0) + 1
                    except ValueError:
                        pass

    for port, count in open_risky.items():
        service = RISKY_PORTS[port]
        sev = "HIGH" if port in [3389, 445, 5900, 4444] else "MEDIUM"
        info = {"port": port, "service": service, "state": "LISTENING/ESTABLISHED"}
        suspicious.append(info)
        findings.append(Finding(
            severity=sev, category="Network",
            title=f"Risky port open: {port}/{service}",
            description=f"Port {port} ({service}) is actively listening or has established connections.",
            remediation=f"netstat -ano | findstr :{port}",
            owner="IT Security",
            attacker_context=f"Port {port} ({service}) is my entry point for remote access.",
            source_files=["network_analysis/active_connections.csv", "netstat_ano.txt"],
        ))

    return suspicious, findings


def parse_smb_shares(files: Dict[str, str]) -> tuple:
    """Parse network_analysis/smb_shares.csv."""
    findings = []
    shares = []
    content = files.get("network_analysis/smb_shares.csv", "")
    if not content:
        return shares, findings

    rows = _parse_csv(content)
    for row in rows:
        name = row.get("Name", "").strip().strip('"')
        path = row.get("Path", "").strip().strip('"')
        description = row.get("Description", "").strip().strip('"')
        shares.append({"name": name, "path": path, "description": description})

    # Flag non-default shares
    default_shares = ["admin$", "c$", "d$", "e$", "ipc$", "print$"]
    custom_shares = [s for s in shares if s["name"].lower() not in default_shares]
    if custom_shares:
        names = ", ".join(s["name"] for s in custom_shares[:5])
        findings.append(Finding(
            severity="MEDIUM", category="Network",
            title=f"{len(custom_shares)} custom SMB share(s)",
            description=f"Non-default SMB shares detected: {names}. Review access permissions.",
            remediation="Get-SmbShare | Where-Object {$_.Special -eq $false} | Format-List",
            owner="IT Security",
            source_files=["network_analysis/smb_shares.csv"],
        ))

    return shares, findings


def build_network_info(files: Dict[str, str]) -> tuple:
    """Build complete network analysis. Returns (NetworkInfo, fw_profiles, findings)."""
    all_findings = []

    fw_profiles, fw_findings = parse_firewall_profiles(files)
    all_findings.extend(fw_findings)

    risky_rules, rule_findings = parse_firewall_rules(files)
    all_findings.extend(rule_findings)

    arp, arp_findings = parse_arp_table(files)
    all_findings.extend(arp_findings)

    connections, conn_findings = parse_active_connections(files)
    all_findings.extend(conn_findings)

    shares, share_findings = parse_smb_shares(files)
    all_findings.extend(share_findings)

    info = NetworkInfo(
        open_ports=connections,
        arp_entries=arp,
        suspicious_connections=connections,
        risky_firewall_rules=risky_rules,
        smb_shares=shares,
    )

    return info, fw_profiles, all_findings
