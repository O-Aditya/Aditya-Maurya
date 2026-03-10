"""Parsers for persistence mechanisms: registry, scheduled tasks, services, startup."""
import csv
import io
import re
from typing import Dict, List
from ..models import Finding, PersistenceInfo


def _parse_csv(content: str) -> List[dict]:
    """Parse a CSV string into list of dicts."""
    if not content or not content.strip():
        return []
    try:
        reader = csv.DictReader(io.StringIO(content))
        return [row for row in reader]
    except Exception:
        return []


def parse_registry_run_keys(files: Dict[str, str]) -> tuple:
    """Parse persistence/registry_run_keys.csv."""
    findings = []
    entries = []
    content = files.get("persistence/registry_run_keys.csv", "")
    if not content:
        return entries, findings

    rows = _parse_csv(content)
    suspicious_paths = ["%appdata%", "%temp%", "%tmp%", "\\appdata\\local\\temp",
                        "\\users\\public", "\\programdata\\", "c:\\temp"]

    for row in rows:
        name = row.get("Name", row.get('"Name"', "")).strip().strip('"')
        value = row.get("Value", row.get('"Value"', "")).strip().strip('"')
        location = row.get("Location", row.get('"Location"', "")).strip().strip('"')

        entry = {"name": name, "value": value, "location": location}
        entries.append(entry)

        # Check for suspicious paths
        value_lower = value.lower()
        if any(sp in value_lower for sp in suspicious_paths):
            findings.append(Finding(
                severity="HIGH", category="Persistence",
                title=f"Suspicious autorun: {name}",
                description=f"Registry run key '{name}' points to suspicious path: {value}. Location: {location}",
                remediation=f'Remove-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" -Name "{name}"',
                owner="IT Security",
                attacker_context="I added myself to Run keys from a temp folder — this survives reboots.",
                source_files=["persistence/registry_run_keys.csv"],
            ))

        # Check for unsigned/unusual executables
        if any(ext in value_lower for ext in [".vbs", ".bat", ".cmd", ".ps1", ".js", ".wsf", ".hta"]):
            findings.append(Finding(
                severity="HIGH", category="Persistence",
                title=f"Script-based autorun: {name}",
                description=f"Registry run key '{name}' executes a script: {value}. Scripts in autoruns are high-risk.",
                remediation=f'Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" | Select-Object {name}',
                owner="IT Security",
                attacker_context="Script autoruns are harder to inspect and can download next-stage payloads.",
                source_files=["persistence/registry_run_keys.csv"],
            ))

    return entries, findings


def parse_scheduled_tasks(files: Dict[str, str]) -> tuple:
    """Parse persistence/non_microsoft_scheduled_tasks.csv."""
    findings = []
    tasks = []
    content = files.get("persistence/non_microsoft_scheduled_tasks.csv", "")
    if not content:
        return tasks, findings

    rows = _parse_csv(content)

    for row in rows:
        name = row.get("TaskName", row.get('"TaskName"', "")).strip().strip('"')
        path = row.get("TaskPath", row.get('"TaskPath"', "")).strip().strip('"')
        author = row.get("Author", row.get('"Author"', "")).strip().strip('"')
        state = row.get("State", row.get('"State"', "")).strip().strip('"')
        actions = row.get("Actions", row.get('"Actions"', "")).strip().strip('"')
        run_as = row.get("Principal", row.get('"Principal"', row.get("UserId", ""))).strip().strip('"')

        task = {"name": name, "path": path, "author": author, "state": state,
                "actions": actions, "run_as": run_as}
        tasks.append(task)

        # Flag suspicious tasks
        actions_lower = actions.lower() if actions else ""
        name_lower = name.lower()

        is_suspicious = False
        reasons = []

        if any(sp in actions_lower for sp in ["%appdata%", "%temp%", "\\users\\public", "\\windows\\temp"]):
            is_suspicious = True
            reasons.append("executes from suspicious path")

        if any(ext in actions_lower for ext in [".vbs", ".bat", ".ps1", ".js", ".wsf", "powershell", "cmd.exe /c"]):
            is_suspicious = True
            reasons.append("executes a script")

        if "system" in run_as.lower():
            reasons.append("runs as SYSTEM")
            if is_suspicious:
                # Elevated + suspicious = CRITICAL
                findings.append(Finding(
                    severity="CRITICAL", category="Persistence",
                    title=f"Suspicious SYSTEM-level task: {name}",
                    description=f"Scheduled task '{name}' runs as SYSTEM and {', '.join(reasons)}. Action: {actions[:200]}. Author: {author}",
                    remediation=f'Unregister-ScheduledTask -TaskName "{name}" -Confirm:$false',
                    owner="IT Security",
                    attacker_context="SYSTEM-level task from suspicious path = full compromise with persistence.",
                    is_compound=True,
                    source_files=["persistence/non_microsoft_scheduled_tasks.csv"],
                ))
        elif is_suspicious:
            findings.append(Finding(
                severity="HIGH", category="Persistence",
                title=f"Suspicious scheduled task: {name}",
                description=f"Task '{name}' {', '.join(reasons)}. Action: {actions[:200]}. Author: {author}",
                remediation=f'Get-ScheduledTask -TaskName "{name}" | Get-ScheduledTaskInfo',
                owner="IT Security",
                source_files=["persistence/non_microsoft_scheduled_tasks.csv"],
            ))

    return tasks, findings


def parse_services(files: Dict[str, str]) -> tuple:
    """Parse persistence/non_standard_services.csv."""
    findings = []
    services = []
    content = files.get("persistence/non_standard_services.csv", "")
    if not content:
        return services, findings

    rows = _parse_csv(content)

    for row in rows:
        name = row.get("Name", row.get('"Name"', "")).strip().strip('"')
        display = row.get("DisplayName", row.get('"DisplayName"', "")).strip().strip('"')
        path = row.get("PathName", row.get('"PathName"', row.get("ImagePath", ""))).strip().strip('"')
        start = row.get("StartType", row.get('"StartType"', row.get("StartMode", ""))).strip().strip('"')
        state = row.get("State", row.get('"State"', row.get("Status", ""))).strip().strip('"')

        service = {"name": name, "display": display, "path": path,
                   "start_type": start, "state": state}
        services.append(service)

        # Flag services from non-standard locations
        path_lower = path.lower() if path else ""
        suspicious_dirs = ["\\appdata\\", "\\users\\public", "\\temp\\", "\\tmp\\",
                           "\\downloads\\", "\\desktop\\"]
        if any(sp in path_lower for sp in suspicious_dirs):
            findings.append(Finding(
                severity="HIGH", category="Persistence",
                title=f"Service in suspicious path: {name}",
                description=f"Service '{display or name}' runs from: {path}. Services should run from Program Files or System32.",
                remediation=f'Get-Service "{name}" | Stop-Service; Set-Service "{name}" -StartupType Disabled',
                owner="IT Security",
                attacker_context="I installed my backdoor as a Windows service. It starts automatically and runs as SYSTEM.",
                source_files=["persistence/non_standard_services.csv"],
            ))

        # Flag unquoted service paths (privilege escalation)
        if path and " " in path and not path.startswith('"') and ".exe" in path_lower:
            findings.append(Finding(
                severity="MEDIUM", category="Persistence",
                title=f"Unquoted service path: {name}",
                description=f"Service '{name}' has an unquoted path with spaces: {path}. This is exploitable for privilege escalation.",
                remediation=f'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\{name}" -Name ImagePath -Value \'"{path}"\'',
                owner="IT Security",
                attacker_context="I can plant a binary in the unquoted path to hijack this service and get SYSTEM.",
                source_files=["persistence/non_standard_services.csv"],
            ))

    return services, findings


def parse_startup_items(files: Dict[str, str]) -> tuple:
    """Parse persistence/startup_folder_files.csv."""
    findings = []
    items = []
    content = files.get("persistence/startup_folder_files.csv", "")
    if not content:
        return items, findings

    rows = _parse_csv(content)
    for row in rows:
        name = row.get("Name", row.get('"Name"', "")).strip().strip('"')
        full_name = row.get("FullName", row.get('"FullName"', "")).strip().strip('"')

        items.append({"name": name, "path": full_name})

        # Flag suspicious startup items
        name_lower = name.lower()
        if any(ext in name_lower for ext in [".vbs", ".bat", ".cmd", ".ps1", ".js", ".exe", ".wsf"]):
            # Executables/scripts in startup folder are suspicious
            if not any(safe in name_lower for safe in ["onenote", "outlook", "teams"]):
                findings.append(Finding(
                    severity="HIGH", category="Persistence",
                    title=f"Executable in startup folder: {name}",
                    description=f"File '{name}' in startup folder at: {full_name}. Executables in startup are a common persistence mechanism.",
                    remediation=f'Remove-Item "{full_name}" -Force',
                    owner="IT Security",
                    attacker_context="Anything in the Startup folder runs at logon. Simple but effective persistence.",
                    source_files=["persistence/startup_folder_files.csv"],
                ))

    return items, findings


def build_persistence_info(files: Dict[str, str]) -> tuple:
    """Build complete persistence analysis. Returns (PersistenceInfo, findings)."""
    all_findings = []

    reg_keys, reg_findings = parse_registry_run_keys(files)
    all_findings.extend(reg_findings)

    tasks, task_findings = parse_scheduled_tasks(files)
    all_findings.extend(task_findings)

    services, svc_findings = parse_services(files)
    all_findings.extend(svc_findings)

    startup, startup_findings = parse_startup_items(files)
    all_findings.extend(startup_findings)

    info = PersistenceInfo(
        registry_run_keys=reg_keys,
        suspicious_tasks=tasks,
        non_standard_services=services,
        startup_items=startup,
    )

    return info, all_findings
