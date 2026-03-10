"""Data models for VOLDEBUG Audit Intelligence System."""
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime


@dataclass
class Finding:
    """A single security finding."""
    severity: str          # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str          # e.g. "Disk Encryption", "Antivirus", "Firewall"
    title: str             # Short title
    description: str       # Detailed description
    remediation: str = ""  # PowerShell/CMD fix command
    owner: str = ""        # IT, Security, Compliance
    attacker_context: str = ""  # "If I were an attacker..."
    machine_name: str = ""
    is_compound: bool = False   # True if this is a compound risk finding
    source_files: list = field(default_factory=list)  # Files that contributed

    @property
    def severity_score(self) -> int:
        return {"CRITICAL": 35, "HIGH": 20, "MEDIUM": 10, "LOW": 3, "INFO": 0}.get(self.severity, 0)


@dataclass
class SecurityPosture:
    """Security status snapshot for a machine."""
    bitlocker_enabled: Optional[bool] = None
    bitlocker_details: str = ""
    defender_running: Optional[bool] = None
    defender_updated: Optional[bool] = None
    defender_exclusions: list = field(default_factory=list)
    edr_detected: bool = False
    edr_name: str = ""
    firewall_domain: Optional[bool] = None
    firewall_private: Optional[bool] = None
    firewall_public: Optional[bool] = None


@dataclass
class SystemInfo:
    """Machine hardware and OS information."""
    hostname: str = ""
    ip: str = ""
    mac: str = ""
    domain: str = ""
    os_name: str = ""
    os_version: str = ""
    os_arch: str = ""
    manufacturer: str = ""
    model: str = ""
    serial: str = ""
    bios_version: str = ""
    last_boot: str = ""
    is_portable: bool = False  # Laptop detection
    is_server: bool = False    # Server/admin workstation detection


@dataclass
class EventSummary:
    """Summary of key security events from event logs."""
    failed_logons: int = 0            # 4625
    explicit_cred_use: int = 0        # 4648
    privilege_logons: int = 0         # 4672
    task_created: int = 0             # 4698
    user_created: int = 0             # 4720
    user_added_to_group: int = 0      # 4732
    ntlm_auth: int = 0               # 4776
    new_service: int = 0              # 7045
    log_cleared: int = 0              # 1102
    defender_rtp_disabled: int = 0    # 5001
    defender_config_changed: int = 0  # 5007
    unclean_shutdown: int = 0         # Event 41
    notable_events: list = field(default_factory=list)  # Top suspicious events


@dataclass
class PersistenceInfo:
    """Persistence mechanism analysis."""
    registry_run_keys: list = field(default_factory=list)
    suspicious_tasks: list = field(default_factory=list)
    non_standard_services: list = field(default_factory=list)
    startup_items: list = field(default_factory=list)


@dataclass
class NetworkInfo:
    """Network exposure analysis."""
    open_ports: list = field(default_factory=list)
    arp_entries: list = field(default_factory=list)
    suspicious_connections: list = field(default_factory=list)
    risky_firewall_rules: list = field(default_factory=list)
    smb_shares: list = field(default_factory=list)


@dataclass
class MachineAudit:
    """Complete audit result for one machine."""
    folder_name: str
    folder_path: str
    collection_time: str = ""
    auditor: str = ""
    file_count: int = 0
    files_available: list = field(default_factory=list)
    files_missing: list = field(default_factory=list)

    system_info: SystemInfo = field(default_factory=SystemInfo)
    security_posture: SecurityPosture = field(default_factory=SecurityPosture)
    event_summary: EventSummary = field(default_factory=EventSummary)
    persistence: PersistenceInfo = field(default_factory=PersistenceInfo)
    network: NetworkInfo = field(default_factory=NetworkInfo)

    installed_software: list = field(default_factory=list)
    local_admins: list = field(default_factory=list)
    stored_credentials: list = field(default_factory=list)
    hotfixes: list = field(default_factory=list)
    last_patch_date: str = ""
    patch_gap_days: int = -1

    findings: list = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "Low"

    analyzed_at: str = field(default_factory=lambda: datetime.now().isoformat())

    @property
    def hostname(self) -> str:
        return self.system_info.hostname or self.folder_name

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "HIGH")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "MEDIUM")

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "LOW")


@dataclass
class FleetSummary:
    """Fleet-wide audit summary."""
    total_machines: int = 0
    machines: list = field(default_factory=list)
    collection_period: str = ""
    generated_at: str = field(default_factory=lambda: datetime.now().isoformat())

    critical_machines: int = 0
    high_machines: int = 0
    medium_machines: int = 0
    low_machines: int = 0

    top_findings: list = field(default_factory=list)       # Most common findings
    systemic_issues: list = field(default_factory=list)     # Affecting 3+ machines
    priority_actions: list = field(default_factory=list)    # Top 5 fleet-wide actions
