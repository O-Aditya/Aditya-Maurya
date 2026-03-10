"""Cross-reference analysis engine and compound risk detection.

This is the brain of VOLDEBUG — it runs all parsers, then cross-references
findings to detect compound risk patterns that individual parsers cannot see.
"""
import re
from typing import Dict, List
from pathlib import Path
from .models import MachineAudit, Finding, FleetSummary
from .loader import load_machine_files, get_file_inventory
from .parsers.system_info import build_system_info
from .parsers.security import parse_bitlocker, parse_defender, parse_edr
from .parsers.events import analyze_events
from .parsers.persistence import build_persistence_info
from .parsers.network import build_network_info
from .parsers.software import (parse_software, parse_local_admins,
                                parse_credentials, parse_hotfixes, parse_local_users)
from .scorer import calculate_risk_score


def analyze_machine(folder_path: str) -> MachineAudit:
    """Run full analysis on a single machine folder.

    This is the main entry point — it:
    1. Loads all files
    2. Runs every parser
    3. Detects compound risk patterns
    4. Calculates final risk score
    """
    path = Path(folder_path)
    files = load_machine_files(path)
    available, missing = get_file_inventory(files)

    audit = MachineAudit(
        folder_name=path.name,
        folder_path=str(path),
        file_count=len(files),
        files_available=available,
        files_missing=missing,
    )

    # --- Parse collection metadata ---
    summary_txt = files.get("summary.txt", "")
    for line in summary_txt.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            k, v = k.strip().lower(), v.strip()
            if "auditor" in k:
                audit.auditor = v
            elif "start time" in k or "collection" in k:
                audit.collection_time = v

    # --- 1. System info ---
    audit.system_info = build_system_info(files)

    # --- 2. Security posture ---
    bl_enabled, bl_details, bl_findings = parse_bitlocker(files)
    audit.security_posture.bitlocker_enabled = bl_enabled
    audit.security_posture.bitlocker_details = bl_details
    audit.findings.extend(bl_findings)

    def_running, def_updated, def_exclusions, def_findings = parse_defender(files)
    audit.security_posture.defender_running = def_running
    audit.security_posture.defender_updated = def_updated
    audit.security_posture.defender_exclusions = def_exclusions
    audit.findings.extend(def_findings)

    edr_detected, edr_name, edr_findings = parse_edr(files)
    audit.security_posture.edr_detected = edr_detected
    audit.security_posture.edr_name = edr_name
    audit.findings.extend(edr_findings)

    # --- 3. Event log analysis ---
    event_summary, event_findings = analyze_events(files)
    audit.event_summary = event_summary
    audit.findings.extend(event_findings)

    # --- 4. Persistence analysis ---
    persistence_info, pers_findings = build_persistence_info(files)
    audit.persistence = persistence_info
    audit.findings.extend(pers_findings)

    # --- 5. Network analysis ---
    network_info, fw_profiles, net_findings = build_network_info(files)
    audit.network = network_info
    if fw_profiles.get("domain") is not None:
        audit.security_posture.firewall_domain = fw_profiles["domain"]
    if fw_profiles.get("private") is not None:
        audit.security_posture.firewall_private = fw_profiles["private"]
    if fw_profiles.get("public") is not None:
        audit.security_posture.firewall_public = fw_profiles["public"]
    audit.findings.extend(net_findings)

    # --- 6. Software & access ---
    software_list, sw_findings = parse_software(files)
    audit.installed_software = software_list
    audit.findings.extend(sw_findings)

    admins, admin_findings = parse_local_admins(files)
    audit.local_admins = admins
    audit.findings.extend(admin_findings)

    creds, cred_findings = parse_credentials(files)
    audit.stored_credentials = creds
    audit.findings.extend(cred_findings)

    user_findings = parse_local_users(files)
    audit.findings.extend(user_findings)

    # --- 7. Patch status ---
    hotfixes, last_patch, gap_days, hf_findings = parse_hotfixes(files, audit.collection_time)
    audit.hotfixes = hotfixes
    audit.last_patch_date = last_patch
    audit.patch_gap_days = gap_days
    audit.findings.extend(hf_findings)

    # --- 8. Compound risk detection ---
    compound_findings = detect_compound_risks(audit)
    audit.findings.extend(compound_findings)

    # --- 9. Calculate risk score ---
    audit.risk_score, audit.risk_level = calculate_risk_score(audit)

    # Set machine name on all findings
    hostname = audit.hostname
    for f in audit.findings:
        f.machine_name = hostname

    return audit


def detect_compound_risks(audit: MachineAudit) -> List[Finding]:
    """Detect the 6 compound risk patterns from the system prompt.

    These ONLY trigger when multiple individual conditions are true together.
    Individual conditions have already been flagged by their respective parsers.
    """
    compounds = []
    sp = audit.security_posture

    # --- Pattern 1: Blind Machine ---
    # Defender stopped + EDR absent + Exclusions on temp folders
    defender_down = sp.defender_running is False
    no_edr = not sp.edr_detected
    dangerous_exclusions = any(
        any(d in e.lower() for d in ["temp", "appdata", "system32", "aact"])
        for e in sp.defender_exclusions
    )

    if defender_down and no_edr:
        compounds.append(Finding(
            severity="CRITICAL", category="Compound Risk",
            title="BLIND MACHINE — No AV + No EDR",
            description="This machine has Defender stopped AND no EDR agent. It is completely unmonitored — malware can execute, persist, and exfiltrate without any detection.",
            remediation="1. Start-Service WinDefend\n2. Deploy EDR agent immediately\n3. Run full offline scan: Start-MpScan -ScanType FullScan",
            owner="IT Security — IMMEDIATE",
            attacker_context="This machine is blind. I can do absolutely anything without being detected.",
            is_compound=True,
            source_files=["defender_status.txt", "edr_candidates_present.txt"],
        ))
    elif no_edr and dangerous_exclusions:
        compounds.append(Finding(
            severity="CRITICAL", category="Compound Risk",
            title="SEMI-BLIND MACHINE — No EDR + Dangerous Exclusions",
            description="No EDR agent AND Defender has exclusions on critical paths. Malware placed in excluded paths will not be detected.",
            remediation="1. Deploy EDR agent\n2. Remove dangerous exclusions: Get-MpPreference | Select -Exp ExclusionPath",
            owner="IT Security — URGENT",
            attacker_context="I just need to drop my payload in an excluded folder. No EDR will catch it.",
            is_compound=True,
            source_files=["defender_preferences.txt", "edr_candidates_present.txt"],
        ))

    # --- Pattern 2: Uncontrolled Remote Access ---
    # AnyDesk/TeamViewer installed + Firewall allows port + No EDR
    has_remote_tool = any(
        f.category == "Software" and "remote access" in f.title.lower()
        for f in audit.findings
    )
    has_open_remote_port = any(
        f.category == "Firewall" and any(str(p) in f.title for p in [7070, 5938, 5900, 3389])
        for f in audit.findings
    )
    if has_remote_tool and (has_open_remote_port or no_edr):
        compounds.append(Finding(
            severity="CRITICAL", category="Compound Risk",
            title="UNCONTROLLED REMOTE ACCESS",
            description="Remote access tool is installed with firewall allowing inbound AND/OR no EDR monitoring. This machine can be remotely controlled without oversight.",
            remediation="1. Audit remote access tool usage with IT\n2. Restrict firewall rules to known IPs\n3. Deploy EDR agent",
            owner="IT Security — URGENT",
            attacker_context="Remote access tool + open port = I can connect anytime, from anywhere, undetected.",
            is_compound=True,
            source_files=["installed_software.csv", "firewall_rules.csv", "edr_candidates_present.txt"],
        ))

    # --- Pattern 3: Brute Force with Valid Target ---
    # Failed logins + NTLM auth + Admin account
    has_failed_logins = audit.event_summary.failed_logons >= 5
    has_ntlm = audit.event_summary.ntlm_auth > 0
    has_admin_target = len(audit.local_admins) > 0
    if has_failed_logins and has_ntlm and has_admin_target:
        compounds.append(Finding(
            severity="HIGH", category="Compound Risk",
            title="LIKELY BRUTE FORCE WITH VALID TARGET",
            description=f"{audit.event_summary.failed_logons} failed logons + NTLM authentication in use + {len(audit.local_admins)} local admin account(s). Pattern consistent with active brute force attack targeting known admin accounts.",
            remediation="1. Lock suspected accounts: Disable-LocalUser -Name '<user>'\n2. Block source IPs in firewall\n3. Enforce account lockout policy: net accounts /lockoutthreshold:5",
            owner="IT Security — URGENT",
            attacker_context="NTLM + known admin accounts + multiple retries = I'm actively cracking passwords.",
            is_compound=True,
            source_files=["events_filtered_Security.csv", "local_admins.csv"],
        ))

    # --- Pattern 4: Persistent Compromise Mechanism ---
    # Scheduled task in APPDATA + Script-based + SYSTEM level
    has_system_task = any(
        f.category == "Persistence" and "system-level" in f.title.lower()
        for f in audit.findings
    )
    # Already caught by persistence parser — flag if multiple persistence vectors
    persistence_findings = [f for f in audit.findings if f.category == "Persistence" and f.severity in ("CRITICAL", "HIGH")]
    if len(persistence_findings) >= 3:
        compounds.append(Finding(
            severity="CRITICAL", category="Compound Risk",
            title="MULTIPLE PERSISTENCE MECHANISMS DETECTED",
            description=f"Found {len(persistence_findings)} high/critical persistence findings (registry keys, scheduled tasks, services). Multiple persistence vectors suggest deliberate or automated implant installation.",
            remediation="Full forensic investigation required. Isolate machine from network.",
            owner="IT Security — IMMEDIATE",
            attacker_context="Multiple persistence = even if you find one, I have backups. Full wipe may be needed.",
            is_compound=True,
            source_files=["persistence/registry_run_keys.csv", "persistence/non_microsoft_scheduled_tasks.csv"],
        ))

    # --- Pattern 5: Data Loss Risk ---
    # BitLocker off + Portable laptop
    bitlocker_off = sp.bitlocker_enabled is False
    is_laptop = audit.system_info.is_portable
    if bitlocker_off and is_laptop:
        compounds.append(Finding(
            severity="CRITICAL", category="Compound Risk",
            title="HIGH DATA LOSS RISK — Unencrypted Laptop",
            description=f"BitLocker is OFF on a portable device ({audit.system_info.manufacturer} {audit.system_info.model}). If this device is lost or stolen, all data is immediately accessible to anyone.",
            remediation="Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly -RecoveryPasswordProtector",
            owner="IT Security — IMMEDIATE",
            attacker_context="Unencrypted laptop = I steal it and have everything. No brute force needed.",
            is_compound=True,
            source_files=["bitlocker_status.txt", "bios.txt"],
        ))

    # --- Pattern 6: Active Compromise Indicators ---
    # Log cleared + New service + Unusual ARP
    log_cleared = audit.event_summary.log_cleared > 0
    new_service = audit.event_summary.new_service > 0
    unusual_arp = len(audit.network.arp_entries) > 50
    if log_cleared and new_service:
        compounds.append(Finding(
            severity="CRITICAL", category="Compound Risk",
            title="ACTIVE COMPROMISE INDICATORS",
            description=f"Audit log cleared (Event 1102) + {audit.event_summary.new_service} new service(s) installed (Event 7045){' + unusual ARP table size' if unusual_arp else ''}. This pattern is consistent with active attacker activity — evidence destruction + persistence installation.",
            remediation="1. ISOLATE THIS MACHINE FROM NETWORK IMMEDIATELY\n2. Preserve memory dump\n3. Check SIEM for backup logs\n4. Initiate incident response",
            owner="IT Security — INCIDENT RESPONSE",
            attacker_context="I cleared the logs after installing my backdoor service. This machine is compromised.",
            is_compound=True,
            source_files=["events_filtered_Security.csv", "events_filtered_System.csv", "arp_a.txt"],
        ))

    return compounds


def analyze_fleet(machine_paths: List[str]) -> tuple:
    """Analyze multiple machines and generate fleet summary.

    Returns (list of MachineAudit, FleetSummary).
    """
    audits = []
    for path in machine_paths:
        try:
            audit = analyze_machine(path)
            audits.append(audit)
        except Exception as e:
            # Create a minimal audit for failed machines
            audit = MachineAudit(
                folder_name=Path(path).name,
                folder_path=path,
            )
            audit.findings.append(Finding(
                severity="HIGH", category="System",
                title="Analysis failed",
                description=f"Failed to analyze this machine: {str(e)}",
                owner="IT",
            ))
            audit.risk_score = -1
            audit.risk_level = "ERROR"
            audits.append(audit)

    # Build fleet summary
    summary = build_fleet_summary(audits)

    return audits, summary


def build_fleet_summary(audits: List[MachineAudit]) -> FleetSummary:
    """Generate fleet-wide summary with cross-machine analysis."""
    fleet = FleetSummary(total_machines=len(audits), machines=audits)

    # Count risk levels
    for a in audits:
        if a.risk_level == "Critical":
            fleet.critical_machines += 1
        elif a.risk_level == "High":
            fleet.high_machines += 1
        elif a.risk_level == "Medium":
            fleet.medium_machines += 1
        else:
            fleet.low_machines += 1

    # Find most common findings (by title)
    finding_counts = {}
    for a in audits:
        seen = set()
        for f in a.findings:
            key = f.title
            if key not in seen:
                finding_counts[key] = finding_counts.get(key, 0) + 1
                seen.add(key)

    top = sorted(finding_counts.items(), key=lambda x: -x[1])[:10]
    fleet.top_findings = [{"title": t, "count": c, "pct": round(100 * c / len(audits), 1)} for t, c in top]

    # Systemic issues (affecting 3+ machines or >50% of fleet)
    threshold = max(3, len(audits) // 2)
    fleet.systemic_issues = [
        {"title": t, "count": c, "pct": round(100 * c / len(audits), 1)}
        for t, c in top if c >= threshold
    ]

    # Priority fleet-wide actions
    actions = []
    if any(a.security_posture.bitlocker_enabled is False for a in audits):
        count = sum(1 for a in audits if a.security_posture.bitlocker_enabled is False)
        actions.append(f"Enable BitLocker on {count} machine(s)")
    if any(not a.security_posture.edr_detected for a in audits):
        count = sum(1 for a in audits if not a.security_posture.edr_detected)
        actions.append(f"Deploy EDR to {count} machine(s)")
    if any(a.security_posture.defender_running is False for a in audits):
        count = sum(1 for a in audits if a.security_posture.defender_running is False)
        actions.append(f"Re-enable Defender on {count} machine(s)")
    if any(a.patch_gap_days > 30 for a in audits):
        count = sum(1 for a in audits if a.patch_gap_days > 30)
        actions.append(f"Patch {count} machine(s) behind >30 days")
    if any(a.critical_count > 0 for a in audits):
        count = sum(1 for a in audits if a.critical_count > 0)
        actions.append(f"Investigate {count} machine(s) with CRITICAL findings")

    fleet.priority_actions = actions[:5]

    return fleet
