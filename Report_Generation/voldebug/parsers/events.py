"""Parser for Windows Event Logs (Security, System, Application CSVs).

VOLDEBUG event CSVs have multi-line Message fields. This parser handles
the tricky multi-line CSV format and extracts security-relevant events.
"""
import re
import csv
import io
from typing import Dict, List
from ..models import Finding, EventSummary


# Critical security Event IDs to look for
SECURITY_EVENT_IDS = {
    1102: ("CRITICAL", "Audit log cleared", "Antivirus", "An audit log was cleared — potential evidence destruction."),
    4625: ("HIGH", "Failed logon attempt", "Authentication", "Failed logon — possible brute force or unauthorized access attempt."),
    4648: ("MEDIUM", "Explicit credential logon", "Authentication", "Logon with explicit credentials — credential forwarding or lateral movement."),
    4672: ("INFO", "Special privileges assigned", "Authentication", "Privileged logon — SYSTEM or admin privileges granted."),
    4698: ("HIGH", "Scheduled task created", "Persistence", "New scheduled task — possible persistence mechanism."),
    4720: ("HIGH", "User account created", "Authentication", "New user account created — check for unauthorized accounts."),
    4724: ("MEDIUM", "Password reset attempt", "Authentication", "Password reset attempted on an account."),
    4732: ("HIGH", "Member added to privileged group", "Authentication", "User added to Administrators or similar privileged group."),
    4776: ("INFO", "NTLM auth validation", "Authentication", "NTLM credential validation — legacy auth protocol in use."),
    5001: ("HIGH", "Defender RTP disabled", "Antivirus", "Defender Real-Time Protection was disabled."),
    5007: ("MEDIUM", "Defender config changed", "Antivirus", "Defender configuration was modified."),
}

SYSTEM_EVENT_IDS = {
    41: ("MEDIUM", "Unclean shutdown", "System Health", "System rebooted without clean shutdown — possible crash or forced reboot."),
    1001: ("MEDIUM", "BSOD/Crash", "System Health", "System crash or bugcheck recorded."),
    6005: ("INFO", "Event log service started", "System Health", "Event log service started — normal boot indicator."),
    6006: ("INFO", "Event log service stopped", "System Health", "Event log service stopped — clean shutdown indicator."),
    7034: ("MEDIUM", "Service crashed", "System Health", "A service terminated unexpectedly."),
    7045: ("HIGH", "New service installed", "Persistence", "A new service was installed on the system — check originating process and service binary."),
}


def parse_event_csv(content: str) -> List[dict]:
    """Parse a VOLDEBUG events_filtered CSV.

    These CSVs have multi-line Message fields enclosed in quotes.
    Format: TimeCreated, Id, LevelDisplayName, ProviderName, Message
    """
    events = []
    if not content or not content.strip():
        return events

    lines = content.splitlines()
    if not lines:
        return events

    # Find the header line
    header_line = None
    header_idx = 0
    for i, line in enumerate(lines):
        if "TimeCreated" in line and "Id" in line:
            header_line = line
            header_idx = i
            break

    if header_line is None:
        return events

    # Use csv reader to handle multi-line quoted fields
    csv_text = "\n".join(lines[header_idx:])
    try:
        reader = csv.DictReader(io.StringIO(csv_text))
        for row in reader:
            try:
                event = {
                    "time": row.get("TimeCreated", row.get('"TimeCreated"', "")).strip().strip('"'),
                    "id": int(row.get("Id", row.get('"Id"', "0")).strip().strip('"')),
                    "level": row.get("LevelDisplayName", row.get('"LevelDisplayName"', "")).strip().strip('"'),
                    "provider": row.get("ProviderName", row.get('"ProviderName"', "")).strip().strip('"'),
                    "message": row.get("Message", row.get('"Message"', "")).strip().strip('"')[:500],
                }
                events.append(event)
            except (ValueError, TypeError):
                continue
    except Exception:
        # Fallback: line-by-line parsing for malformed CSVs
        return _fallback_parse_events(lines[header_idx + 1:])

    return events


def _fallback_parse_events(lines: List[str]) -> List[dict]:
    """Fallback parser for event CSVs with complex quoting."""
    events = []
    current_parts = []
    in_quote = False

    for line in lines:
        if not in_quote:
            # Start of a new record
            quote_count = line.count('"')
            if quote_count % 2 == 0:
                # Complete record on one line
                parts = line.split(",", 4)
                if len(parts) >= 2:
                    try:
                        event_id = int(parts[1].strip().strip('"'))
                        events.append({
                            "time": parts[0].strip().strip('"'),
                            "id": event_id,
                            "level": parts[2].strip().strip('"') if len(parts) > 2 else "",
                            "provider": parts[3].strip().strip('"') if len(parts) > 3 else "",
                            "message": parts[4].strip().strip('"')[:500] if len(parts) > 4 else "",
                        })
                    except (ValueError, IndexError):
                        pass
            else:
                # Start of multi-line record
                current_parts = [line]
                in_quote = True
        else:
            current_parts.append(line)
            # Check if this closes the quote
            combined = "\n".join(current_parts)
            if combined.count('"') % 2 == 0:
                in_quote = False
                parts = combined.split(",", 4)
                if len(parts) >= 2:
                    try:
                        event_id = int(parts[1].strip().strip('"'))
                        events.append({
                            "time": parts[0].strip().strip('"'),
                            "id": event_id,
                            "level": parts[2].strip().strip('"') if len(parts) > 2 else "",
                            "provider": parts[3].strip().strip('"') if len(parts) > 3 else "",
                            "message": parts[4].strip().strip('"')[:500] if len(parts) > 4 else "",
                        })
                    except (ValueError, IndexError):
                        pass

    return events


def analyze_events(files: Dict[str, str]) -> tuple:
    """Analyze all event log CSVs. Returns (EventSummary, findings)."""
    summary = EventSummary()
    findings = []

    # Process Security events
    sec_events = parse_event_csv(files.get("events_filtered_Security.csv", ""))
    for ev in sec_events:
        eid = ev["id"]
        if eid == 4625:
            summary.failed_logons += 1
        elif eid == 4648:
            summary.explicit_cred_use += 1
        elif eid == 4672:
            summary.privilege_logons += 1
        elif eid == 4698:
            summary.task_created += 1
        elif eid == 4720:
            summary.user_created += 1
        elif eid == 4732:
            summary.user_added_to_group += 1
        elif eid == 4776:
            summary.ntlm_auth += 1
        elif eid == 1102:
            summary.log_cleared += 1
        elif eid == 5001:
            summary.defender_rtp_disabled += 1
        elif eid == 5007:
            summary.defender_config_changed += 1

        # Collect notable events
        if eid in SECURITY_EVENT_IDS:
            sev, title, cat, desc = SECURITY_EVENT_IDS[eid]
            if sev in ("CRITICAL", "HIGH"):
                summary.notable_events.append({
                    "time": ev["time"], "id": eid, "severity": sev,
                    "title": title, "message": ev["message"][:200]
                })

    # Process System events
    sys_events = parse_event_csv(files.get("events_filtered_System.csv", ""))
    for ev in sys_events:
        eid = ev["id"]
        if eid == 41:
            summary.unclean_shutdown += 1
        elif eid == 7045:
            summary.new_service += 1

        if eid in SYSTEM_EVENT_IDS:
            sev, title, cat, desc = SYSTEM_EVENT_IDS[eid]
            if sev in ("CRITICAL", "HIGH", "MEDIUM"):
                summary.notable_events.append({
                    "time": ev["time"], "id": eid, "severity": sev,
                    "title": title, "message": ev["message"][:200]
                })

    # Generate findings from counts
    if summary.log_cleared > 0:
        findings.append(Finding(
            severity="CRITICAL", category="Event Logs",
            title=f"Audit log cleared ({summary.log_cleared}x)",
            description=f"Security audit log was cleared {summary.log_cleared} time(s) (Event 1102). This is a strong indicator of evidence destruction.",
            remediation="wevtutil qe Security /q:\"*[System[EventID=1102]]\" /f:text",
            owner="IT Security",
            attacker_context="I cleared the logs to hide my tracks. Check backup SIEM for the real events.",
            source_files=["events_filtered_Security.csv"],
        ))

    if summary.failed_logons >= 5:
        sev = "CRITICAL" if summary.failed_logons >= 20 else "HIGH" if summary.failed_logons >= 10 else "MEDIUM"
        findings.append(Finding(
            severity=sev, category="Authentication",
            title=f"{summary.failed_logons} failed logon attempts",
            description=f"Detected {summary.failed_logons} failed logon events (Event 4625). Possible brute force attack.",
            remediation="Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} | Select-Object TimeCreated, @{N='Target';E={$_.Properties[5].Value}}, @{N='Source';E={$_.Properties[19].Value}} | Sort-Object TimeCreated -Descending | Select-Object -First 20",
            owner="IT Security",
            attacker_context="I'm trying different passwords against this machine. If threshold is low, I'll succeed eventually.",
            source_files=["events_filtered_Security.csv"],
        ))

    if summary.user_created > 0:
        findings.append(Finding(
            severity="HIGH", category="Authentication",
            title=f"{summary.user_created} new user account(s) created",
            description=f"Detected {summary.user_created} user creation events (Event 4720). Verify these are authorized.",
            remediation="Get-WinEvent -FilterHashtable @{LogName='Security';Id=4720} | Format-List TimeCreated, Message",
            owner="IT Security",
            attacker_context="I created a backdoor account for persistent access.",
            source_files=["events_filtered_Security.csv"],
        ))

    if summary.user_added_to_group > 0:
        findings.append(Finding(
            severity="HIGH", category="Authentication",
            title=f"User added to privileged group ({summary.user_added_to_group}x)",
            description=f"Detected {summary.user_added_to_group} events of users being added to privileged groups (Event 4732).",
            remediation="Get-WinEvent -FilterHashtable @{LogName='Security';Id=4732} | Format-List TimeCreated, Message",
            owner="IT Security",
            attacker_context="I escalated my account to admin for full control.",
            source_files=["events_filtered_Security.csv"],
        ))

    if summary.new_service > 0:
        sev = "HIGH" if summary.new_service >= 3 else "MEDIUM"
        findings.append(Finding(
            severity=sev, category="Persistence",
            title=f"{summary.new_service} new service(s) installed",
            description=f"Detected {summary.new_service} service installation events (Event 7045). New services can be persistence mechanisms.",
            remediation="Get-WinEvent -FilterHashtable @{LogName='System';Id=7045} | Format-List TimeCreated, Message",
            owner="IT Security",
            attacker_context="I installed a service to survive reboots. Check the service binary path.",
            source_files=["events_filtered_System.csv"],
        ))

    if summary.task_created > 0:
        findings.append(Finding(
            severity="HIGH", category="Persistence",
            title=f"{summary.task_created} scheduled task(s) created via event log",
            description=f"Detected {summary.task_created} task creation events (Event 4698). Scheduled tasks are common persistence.",
            remediation="Get-WinEvent -FilterHashtable @{LogName='Security';Id=4698} | Format-List TimeCreated, Message",
            owner="IT Security",
            source_files=["events_filtered_Security.csv"],
        ))

    if summary.defender_rtp_disabled > 0:
        findings.append(Finding(
            severity="HIGH", category="Antivirus",
            title=f"Defender RTP disabled {summary.defender_rtp_disabled}x in event logs",
            description=f"Real-Time Protection was disabled {summary.defender_rtp_disabled} time(s) (Event 5001).",
            remediation="Set-MpPreference -DisableRealtimeMonitoring $false",
            owner="IT Security",
            attacker_context="I disabled real-time protection to run my payload.",
            source_files=["events_filtered_Security.csv"],
        ))

    if summary.explicit_cred_use >= 5:
        findings.append(Finding(
            severity="MEDIUM", category="Authentication",
            title=f"{summary.explicit_cred_use} explicit credential logins",
            description=f"Detected {summary.explicit_cred_use} explicit credential events (Event 4648). This indicates runas or credential delegation.",
            remediation="Get-WinEvent -FilterHashtable @{LogName='Security';Id=4648} | Select-Object TimeCreated, @{N='Account';E={$_.Properties[1].Value}}, @{N='Target';E={$_.Properties[5].Value}}",
            owner="IT Security",
            source_files=["events_filtered_Security.csv"],
        ))

    if summary.unclean_shutdown > 0:
        findings.append(Finding(
            severity="MEDIUM", category="System Health",
            title=f"{summary.unclean_shutdown} unclean shutdown(s)",
            description=f"System had {summary.unclean_shutdown} unexpected shutdown(s) (Event 41). Possible crash or forced reboot.",
            remediation="Get-WinEvent -FilterHashtable @{LogName='System';Id=41} | Format-List TimeCreated, Message",
            owner="IT",
            source_files=["events_filtered_System.csv"],
        ))

    # Trim notable events to top 20
    summary.notable_events = sorted(
        summary.notable_events,
        key=lambda e: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(e.get("severity", "INFO"), 5)
    )[:20]

    return summary, findings
