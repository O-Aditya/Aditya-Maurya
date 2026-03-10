"""Folder discovery and file loading for VOLDEBUG audit data."""
import os
from pathlib import Path
from typing import List, Dict, Optional


# Expected files in a VOLDEBUG machine folder
EXPECTED_FILES = [
    "bios.txt", "ipconfig_all.txt", "bitlocker_status.txt",
    "defender_status.txt", "defender_preferences.txt",
    "edr_candidates_present.txt", "installed_software.csv",
    "local_admins.csv", "firewall_profiles.txt", "firewall_rules.csv",
    "cmdkey_list.txt", "installed_hotfixes.txt", "os_summary.txt",
    "systeminfo.txt", "summary.txt", "collector_runlog.txt",
    "arp_a.txt", "netstat_ano.txt", "services_running.csv",
    "local_users_passwordinfo.csv", "volumes.txt",
    "events_filtered_Security.csv", "events_filtered_System.csv",
    "events_filtered_Application.csv",
]

# Subfolder files to also load
SUBFOLDER_FILES = {
    "persistence": [
        "registry_run_keys.csv", "non_microsoft_scheduled_tasks.csv",
        "non_standard_services.csv", "startup_folder_files.csv",
        "wmi_event_consumers.csv", "wmi_event_filters.csv",
        "wmi_filter_bindings.csv",
    ],
    "network_analysis": [
        "active_connections.csv", "dns_cache.csv", "hosts_file.txt",
        "smb_shares.csv",
    ],
    "risk_signals": [
        "errors.txt", "rdp_lsm_filtered.csv",
        "successful_logins_interactive.csv",
        "powershell_operational_filtered.csv",
        "startup_commands.csv", "prefetch_listing.csv",
        "recent_documents.csv", "usb_disks.csv",
        "large_archives_recent.csv",
    ],
    "security_audit": [
        "process_creation_audit.csv",
    ],
}


def is_voldebug_folder(path: Path) -> bool:
    """Check if a folder looks like a VOLDEBUG machine audit folder."""
    if not path.is_dir():
        return False
    # Must have at least some expected files
    found = sum(1 for f in EXPECTED_FILES if (path / f).exists())
    return found >= 3  # At least 3 expected files present


def discover_machine_folders(root_path: str) -> List[Path]:
    """Discover all VOLDEBUG machine folders under a root path.

    Supports:
    - Single machine folder passed directly
    - Parent folder containing multiple machine folders
    - Nested structures
    """
    root = Path(root_path)
    if not root.exists():
        return []

    # Check if root itself is a machine folder
    if is_voldebug_folder(root):
        return [root]

    # Check immediate children
    machines = []
    for child in sorted(root.iterdir()):
        if child.is_dir():
            if is_voldebug_folder(child):
                machines.append(child)
            else:
                # Check one more level deep
                for grandchild in sorted(child.iterdir()):
                    if grandchild.is_dir() and is_voldebug_folder(grandchild):
                        machines.append(grandchild)

    return machines


def load_machine_files(machine_path: Path) -> Dict[str, str]:
    """Load all text/csv files from a machine folder into a dict.

    Returns dict mapping relative file path -> file content.
    Keys use forward slashes for subfolder files, e.g.:
        "bios.txt" -> content
        "persistence/registry_run_keys.csv" -> content
    """
    files = {}

    # Load root-level files
    for name in EXPECTED_FILES:
        fpath = machine_path / name
        if fpath.exists():
            try:
                files[name] = fpath.read_text(encoding="utf-8", errors="replace")
            except Exception:
                files[name] = ""

    # Also load any events_filtered_* files that might have other names
    for fpath in machine_path.glob("events_filtered_*.csv"):
        key = fpath.name
        if key not in files:
            try:
                files[key] = fpath.read_text(encoding="utf-8", errors="replace")
            except Exception:
                pass

    # Load subfolder files
    for subfolder, filenames in SUBFOLDER_FILES.items():
        sub_path = machine_path / subfolder
        if sub_path.is_dir():
            for name in filenames:
                fpath = sub_path / name
                if fpath.exists():
                    key = f"{subfolder}/{name}"
                    try:
                        files[key] = fpath.read_text(encoding="utf-8", errors="replace")
                    except Exception:
                        files[key] = ""
            # Also load any other CSV/TXT files in the subfolder
            for fpath in sub_path.glob("*"):
                if fpath.is_file() and fpath.suffix.lower() in (".csv", ".txt", ".json"):
                    key = f"{subfolder}/{fpath.name}"
                    if key not in files:
                        try:
                            files[key] = fpath.read_text(encoding="utf-8", errors="replace")
                        except Exception:
                            pass

    return files


def get_file_inventory(files: Dict[str, str]) -> tuple:
    """Return (available_files, missing_files) from expected files."""
    available = [f for f in EXPECTED_FILES if f in files]
    missing = [f for f in EXPECTED_FILES if f not in files]

    # Add subfolder files
    for subfolder, filenames in SUBFOLDER_FILES.items():
        for name in filenames:
            key = f"{subfolder}/{name}"
            if key in files:
                available.append(key)

    return available, missing
