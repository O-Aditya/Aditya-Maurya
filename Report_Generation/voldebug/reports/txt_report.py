"""TXT report generator matching the system prompt report format."""
from ..models import MachineAudit, FleetSummary


def generate_machine_report(audit: MachineAudit) -> str:
    """Generate per-machine TXT report per system prompt spec."""
    lines = []
    sinfo = audit.system_info
    sp = audit.security_posture

    # Header
    lines.append("=" * 80)
    lines.append(f"  VOLDEBUG SECURITY AUDIT REPORT")
    lines.append(f"  Machine: {audit.hostname}")
    lines.append("=" * 80)
    lines.append("")

    # Executive summary
    lines.append("EXECUTIVE SUMMARY")
    lines.append("-" * 40)
    lines.append(f"  Risk Score:    {audit.risk_score}/100 ({audit.risk_level})")
    lines.append(f"  CRITICAL:      {audit.critical_count} finding(s)")
    lines.append(f"  HIGH:          {audit.high_count} finding(s)")
    lines.append(f"  MEDIUM:        {audit.medium_count} finding(s)")
    lines.append(f"  LOW:           {audit.low_count} finding(s)")
    lines.append(f"  Total:         {len(audit.findings)} finding(s)")
    lines.append("")

    # System overview
    lines.append("SYSTEM OVERVIEW")
    lines.append("-" * 40)
    lines.append(f"  Hostname:      {sinfo.hostname}")
    lines.append(f"  IP Address:    {sinfo.ip}")
    lines.append(f"  MAC Address:   {sinfo.mac}")
    lines.append(f"  OS:            {sinfo.os_name} {sinfo.os_version}")
    lines.append(f"  Architecture:  {sinfo.os_arch}")
    lines.append(f"  Manufacturer:  {sinfo.manufacturer}")
    lines.append(f"  Model:         {sinfo.model}")
    lines.append(f"  Serial:        {sinfo.serial}")
    lines.append(f"  Domain:        {sinfo.domain or 'WORKGROUP'}")
    lines.append(f"  Last Boot:     {sinfo.last_boot}")
    lines.append(f"  Collection:    {audit.collection_time}")
    lines.append(f"  Auditor:       {audit.auditor}")
    lines.append("")

    # Security posture snapshot
    lines.append("SECURITY POSTURE SNAPSHOT")
    lines.append("-" * 40)
    bl = "ON" if sp.bitlocker_enabled else "OFF" if sp.bitlocker_enabled is False else "UNKNOWN"
    df = "Running" if sp.defender_running else "STOPPED" if sp.defender_running is False else "UNKNOWN"
    edr = sp.edr_name if sp.edr_detected else "NOT DETECTED"
    fw_d = "ON" if sp.firewall_domain else "OFF" if sp.firewall_domain is False else "N/A"
    fw_p = "ON" if sp.firewall_private else "OFF" if sp.firewall_private is False else "N/A"
    fw_u = "ON" if sp.firewall_public else "OFF" if sp.firewall_public is False else "N/A"

    lines.append(f"  BitLocker:     {bl}")
    lines.append(f"  Defender:      {df}")
    lines.append(f"  EDR/XDR:       {edr}")
    lines.append(f"  Firewall:      Domain={fw_d} | Private={fw_p} | Public={fw_u}")
    lines.append(f"  Last Patch:    {audit.last_patch_date or 'Unknown'} ({audit.patch_gap_days}d ago)" if audit.patch_gap_days >= 0 else f"  Last Patch:    {audit.last_patch_date or 'Unknown'}")
    lines.append(f"  Local Admins:  {len(audit.local_admins)}")
    lines.append(f"  Stored Creds:  {len(audit.stored_credentials)}")
    if sp.defender_exclusions:
        lines.append(f"  AV Exclusions: {len(sp.defender_exclusions)}")
        for excl in sp.defender_exclusions[:5]:
            lines.append(f"    - {excl}")
    lines.append("")

    # Findings by severity
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        sev_findings = [f for f in audit.findings if f.severity == severity]
        if not sev_findings:
            continue

        lines.append(f"{severity} FINDINGS ({len(sev_findings)})")
        lines.append("-" * 40)
        for i, f in enumerate(sev_findings, 1):
            prefix = "[COMPOUND] " if f.is_compound else ""
            lines.append(f"  {i}. {prefix}{f.title}")
            lines.append(f"     Category: {f.category}")
            lines.append(f"     {f.description}")
            if f.attacker_context:
                lines.append(f"     Attacker POV: {f.attacker_context}")
            if f.remediation:
                lines.append(f"     FIX: {f.remediation}")
            if f.owner:
                lines.append(f"     Owner: {f.owner}")
            lines.append("")
        lines.append("")

    # Event log highlights
    if audit.event_summary.notable_events:
        lines.append("EVENT LOG HIGHLIGHTS")
        lines.append("-" * 40)
        es = audit.event_summary
        lines.append(f"  Failed Logons (4625):     {es.failed_logons}")
        lines.append(f"  Explicit Creds (4648):    {es.explicit_cred_use}")
        lines.append(f"  Privilege Use (4672):     {es.privilege_logons}")
        lines.append(f"  Tasks Created (4698):     {es.task_created}")
        lines.append(f"  Users Created (4720):     {es.user_created}")
        lines.append(f"  Group Changes (4732):     {es.user_added_to_group}")
        lines.append(f"  NTLM Auth (4776):         {es.ntlm_auth}")
        lines.append(f"  New Services (7045):      {es.new_service}")
        lines.append(f"  Logs Cleared (1102):      {es.log_cleared}")
        lines.append(f"  Unclean Shutdowns (41):   {es.unclean_shutdown}")
        lines.append("")

    # Persistence analysis
    pers = audit.persistence
    if pers.registry_run_keys or pers.suspicious_tasks or pers.non_standard_services:
        lines.append("PERSISTENCE ANALYSIS")
        lines.append("-" * 40)
        lines.append(f"  Registry Run Keys:      {len(pers.registry_run_keys)}")
        lines.append(f"  Non-MS Scheduled Tasks: {len(pers.suspicious_tasks)}")
        lines.append(f"  Non-Standard Services:  {len(pers.non_standard_services)}")
        lines.append(f"  Startup Items:          {len(pers.startup_items)}")
        lines.append("")

    # Remediation plan
    rem_findings = [f for f in audit.findings if f.remediation and f.severity in ("CRITICAL", "HIGH")]
    if rem_findings:
        lines.append("REMEDIATION PLAN (Priority Order)")
        lines.append("-" * 40)
        for i, f in enumerate(rem_findings, 1):
            lines.append(f"  {i}. [{f.severity}] {f.title}")
            lines.append(f"     Command: {f.remediation}")
            lines.append(f"     Owner: {f.owner}")
            lines.append("")

    # Missing files
    if audit.files_missing:
        lines.append("DATA GAPS (Missing Files)")
        lines.append("-" * 40)
        for f in audit.files_missing[:10]:
            lines.append(f"  - {f}")
        lines.append("")

    lines.append("=" * 80)
    lines.append(f"  Generated by VOLDEBUG Audit Intelligence System v1.0")
    lines.append(f"  Analyzed: {audit.analyzed_at}")
    lines.append("=" * 80)

    return "\n".join(lines)


def generate_fleet_report(summary: FleetSummary) -> str:
    """Generate fleet-wide summary TXT report."""
    lines = []
    lines.append("=" * 80)
    lines.append("  VOLDEBUG FLEET SECURITY AUDIT SUMMARY")
    lines.append("=" * 80)
    lines.append("")

    lines.append("FLEET OVERVIEW")
    lines.append("-" * 40)
    lines.append(f"  Total Machines:   {summary.total_machines}")
    lines.append(f"  CRITICAL Risk:    {summary.critical_machines}")
    lines.append(f"  HIGH Risk:        {summary.high_machines}")
    lines.append(f"  MEDIUM Risk:      {summary.medium_machines}")
    lines.append(f"  LOW Risk:         {summary.low_machines}")
    lines.append(f"  Generated:        {summary.generated_at}")
    lines.append("")

    # Ranked machines
    ranked = sorted(summary.machines, key=lambda m: m.risk_score, reverse=True)
    lines.append("MACHINES BY RISK (Top 10)")
    lines.append("-" * 40)
    for i, m in enumerate(ranked[:10], 1):
        lines.append(f"  {i}. {m.hostname:<30} Score: {m.risk_score}/100 ({m.risk_level})")
        lines.append(f"     CRITICAL={m.critical_count} HIGH={m.high_count} MED={m.medium_count} LOW={m.low_count}")
    lines.append("")

    # Most common findings
    if summary.top_findings:
        lines.append("TOP FINDINGS ACROSS FLEET")
        lines.append("-" * 40)
        for tf in summary.top_findings:
            lines.append(f"  - {tf['title']}: {tf['count']}/{summary.total_machines} machines ({tf['pct']}%)")
        lines.append("")

    # Systemic issues
    if summary.systemic_issues:
        lines.append("SYSTEMIC ISSUES (Affecting 3+ Machines)")
        lines.append("-" * 40)
        for si in summary.systemic_issues:
            lines.append(f"  ** {si['title']}: {si['count']} machines ({si['pct']}%)")
        lines.append("")

    # Priority actions
    if summary.priority_actions:
        lines.append("PRIORITY FLEET-WIDE ACTIONS")
        lines.append("-" * 40)
        for i, action in enumerate(summary.priority_actions, 1):
            lines.append(f"  {i}. {action}")
        lines.append("")

    lines.append("=" * 80)
    lines.append(f"  Generated by VOLDEBUG Audit Intelligence System v1.0")
    lines.append("=" * 80)

    return "\n".join(lines)
