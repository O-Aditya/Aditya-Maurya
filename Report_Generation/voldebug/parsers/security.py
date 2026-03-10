"""Parsers for security tools: BitLocker, Defender, EDR."""
import re
from typing import Dict, List
from ..models import Finding, SecurityPosture


def parse_bitlocker(files: Dict[str, str]) -> tuple:
    """Parse bitlocker_status.txt. Returns (enabled_bool, details_str, findings)."""
    findings = []
    content = files.get("bitlocker_status.txt", "")

    if not content:
        findings.append(Finding(
            severity="MEDIUM", category="Disk Encryption",
            title="BitLocker status unknown",
            description="bitlocker_status.txt was not collected. Cannot determine disk encryption status.",
            remediation="Re-run VOLDEBUG collector to capture BitLocker status.",
            owner="IT Security",
            attacker_context="If the device is stolen, I cannot tell if the data is encrypted.",
            source_files=["bitlocker_status.txt"],
        ))
        return None, "UNKNOWN — not collected", findings

    # Check each volume
    volumes = re.split(r'Volume [A-Z]:', content)
    os_volume_encrypted = False
    unencrypted_volumes = []

    for i, vol_text in enumerate(volumes):
        if not vol_text.strip():
            continue

        # Find volume letter from preceding text
        vol_match = re.search(r'Volume ([A-Z]):', content[:content.find(vol_text)])
        vol_letter = vol_match.group(1) if vol_match else f"#{i}"

        is_os = "[OS Volume]" in vol_text
        protection_on = "Protection On" in vol_text or "Protection Status:    Protection On" in vol_text

        if is_os and protection_on:
            os_volume_encrypted = True
        elif is_os and not protection_on:
            unencrypted_volumes.insert(0, f"{vol_letter}: (OS Volume)")
        elif not protection_on and "Protection Off" in vol_text:
            unencrypted_volumes.append(f"{vol_letter}:")

    if unencrypted_volumes:
        vol_list = ", ".join(unencrypted_volumes)
        is_os_unencrypted = any("OS" in v for v in unencrypted_volumes)
        sev = "CRITICAL" if is_os_unencrypted else "HIGH"
        findings.append(Finding(
            severity=sev, category="Disk Encryption",
            title=f"BitLocker DISABLED on {len(unencrypted_volumes)} volume(s)",
            description=f"BitLocker is OFF on: {vol_list}. Data at rest is unprotected. If device is lost/stolen, all data is immediately accessible.",
            remediation=f'Enable-BitLocker -MountPoint "{unencrypted_volumes[0].replace(" (OS Volume)", "").strip()}" -EncryptionMethod XtsAes256 -UsedSpaceOnly',
            owner="IT Security",
            attacker_context="Physical access = full data access. I would boot from USB and copy everything.",
            source_files=["bitlocker_status.txt"],
        ))

    enabled = os_volume_encrypted
    details = "Protected" if enabled else f"DISABLED on {', '.join(unencrypted_volumes)}"
    return enabled, details, findings


def parse_defender(files: Dict[str, str]) -> tuple:
    """Parse defender_status.txt and defender_preferences.txt.
    Returns (SecurityPosture fields, findings).
    """
    findings = []
    status_txt = files.get("defender_status.txt", "")
    prefs_txt = files.get("defender_preferences.txt", "")

    running = None
    updated = None
    exclusions = []

    # Parse defender_status.txt
    if not status_txt:
        findings.append(Finding(
            severity="MEDIUM", category="Antivirus",
            title="Defender status unknown",
            description="defender_status.txt was not collected.",
            remediation="Re-run VOLDEBUG collector.",
            owner="IT Security",
            source_files=["defender_status.txt"],
        ))
    else:
        # Check various status indicators
        lines = {l.split(":")[0].strip().lower(): l.split(":", 1)[1].strip()
                 for l in status_txt.splitlines() if ":" in l}

        # Real-time protection
        rtp = lines.get("realtimeprotectionenabled", "")
        am_enabled = lines.get("amserviceenabled", "")
        av_enabled = lines.get("antivirusenabled", "")
        svc_status = lines.get("service status", "")

        if rtp.lower() == "true" or am_enabled.lower() == "true":
            running = True
        elif rtp.lower() == "false" or am_enabled.lower() == "false":
            running = False
        elif "running" in svc_status.lower():
            running = True
        elif "stopped" in svc_status.lower():
            running = False

        # Definition status
        def_status = lines.get("definition status", "")
        if "up" in def_status.lower() and "date" in def_status.lower():
            updated = True
        elif "outdated" in def_status.lower():
            updated = False
            days_match = re.search(r'(\d+)\s*days?', def_status)
            days_str = days_match.group(1) if days_match else "Unknown"
            findings.append(Finding(
                severity="HIGH", category="Antivirus",
                title="Defender definitions outdated",
                description=f"Defender definitions are {days_str} days old. Machine may miss recent threat signatures.",
                remediation="Update-MpSignature -UpdateSource MicrosoftUpdateServer",
                owner="IT Security",
                attacker_context="Outdated definitions = my malware won't be detected by signature scans.",
                source_files=["defender_status.txt"],
            ))

        # Check for threats
        threats = lines.get("threat status", "")
        threat_match = re.search(r'(\d+)\s*threats?', threats)
        if threat_match and int(threat_match.group(1)) > 0:
            findings.append(Finding(
                severity="HIGH", category="Antivirus",
                title=f"{threat_match.group(0)} in quarantine",
                description=f"Defender has {threat_match.group(0)} in scan history. Review quarantine immediately.",
                remediation="Get-MpThreatDetection | Format-List",
                owner="IT Security",
                attacker_context="Previous malware detected means this machine was already targeted or compromised.",
                source_files=["defender_status.txt"],
            ))

        # Full scan age
        full_scan = lines.get("fullscanage", "")
        if full_scan and full_scan.isdigit() and int(full_scan) == 4294967295:
            findings.append(Finding(
                severity="MEDIUM", category="Antivirus",
                title="No full scan ever performed",
                description="FullScanAge is max value — no full malware scan has ever been run on this machine.",
                remediation="Start-MpScan -ScanType FullScan",
                owner="IT Security",
                attacker_context="No full scan means dormant malware could exist undetected anywhere on disk.",
                source_files=["defender_status.txt"],
            ))

        if running is False:
            findings.append(Finding(
                severity="CRITICAL", category="Antivirus",
                title="Windows Defender is NOT running",
                description="Defender service is stopped. This machine has NO active malware protection.",
                remediation="Set-Service -Name WinDefend -StartupType Automatic; Start-Service WinDefend",
                owner="IT Security",
                attacker_context="No AV = I can run any malware without detection. This machine is fully blind.",
                source_files=["defender_status.txt"],
            ))

    # Parse defender_preferences.txt for exclusions
    if prefs_txt:
        # Find ExclusionPath
        excl_match = re.search(r'ExclusionPath\s*:\s*\{?([^}]+)\}?', prefs_txt, re.IGNORECASE)
        if excl_match:
            raw = excl_match.group(1)
            excl_list = [e.strip().strip(",").strip() for e in raw.split("\n") if e.strip() and e.strip() not in ["{", "}"]]
            # Clean up
            exclusions = [e for e in excl_list if e and len(e) > 2]

            if exclusions:
                # Check for dangerous exclusions
                dangerous = []
                for excl in exclusions:
                    excl_lower = excl.lower()
                    if any(d in excl_lower for d in [
                        "system32", "syswow64", "\\temp", "\\tmp",
                        "appdata", "programdata", "aact", "kms",
                        "sppextcomobj", "setup\\scripts",
                        "c:\\windows\\", "c:\\users\\"
                    ]):
                        dangerous.append(excl)

                if dangerous:
                    findings.append(Finding(
                        severity="CRITICAL", category="Antivirus",
                        title=f"Dangerous Defender exclusions ({len(dangerous)} paths)",
                        description=f"Defender is excluding critical system paths from scanning: {'; '.join(dangerous)}. Malware in these locations will NOT be detected. This may indicate KMS/activation tools or deliberate AV evasion.",
                        remediation=f"Remove-MpPreference -ExclusionPath '{dangerous[0]}'",
                        owner="IT Security",
                        attacker_context="I would place my payload in an excluded path — it will never be scanned. These exclusions are effectively disabling AV for those locations.",
                        source_files=["defender_preferences.txt"],
                    ))
                elif exclusions:
                    findings.append(Finding(
                        severity="MEDIUM", category="Antivirus",
                        title=f"{len(exclusions)} Defender exclusion(s) configured",
                        description=f"Defender exclusions are set: {'; '.join(exclusions[:5])}{'...' if len(exclusions) > 5 else ''}. Review for necessity.",
                        remediation="Get-MpPreference | Select-Object -ExpandProperty ExclusionPath",
                        owner="IT Security",
                        source_files=["defender_preferences.txt"],
                    ))

        # Check other risky settings
        if "DisableRealtimeMonitoring" in prefs_txt:
            rtm = re.search(r'DisableRealtimeMonitoring\s*:\s*(\w+)', prefs_txt)
            if rtm and rtm.group(1).lower() == "true":
                running = False
                findings.append(Finding(
                    severity="CRITICAL", category="Antivirus",
                    title="Real-time monitoring DISABLED in Defender preferences",
                    description="DisableRealtimeMonitoring is set to True. Malware can execute without detection.",
                    remediation="Set-MpPreference -DisableRealtimeMonitoring $false",
                    owner="IT Security",
                    attacker_context="Real-time monitoring disabled = I can execute any payload live.",
                    source_files=["defender_preferences.txt"],
                ))

        if "DisableRemovableDriveScanning" in prefs_txt:
            rds = re.search(r'DisableRemovableDriveScanning\s*:\s*(\w+)', prefs_txt)
            if rds and rds.group(1).lower() == "true":
                findings.append(Finding(
                    severity="MEDIUM", category="Antivirus",
                    title="Removable drive scanning disabled",
                    description="Defender will not scan USB drives. Malware can be introduced via removable media.",
                    remediation="Set-MpPreference -DisableRemovableDriveScanning $false",
                    owner="IT Security",
                    source_files=["defender_preferences.txt"],
                ))

        # PUAProtection
        pua = re.search(r'PUAProtection\s*:\s*(\d+)', prefs_txt)
        if pua and pua.group(1) == "0":
            findings.append(Finding(
                severity="LOW", category="Antivirus",
                title="PUA protection disabled",
                description="Potentially Unwanted Application (PUA) protection is off. Adware/bloatware will not be flagged.",
                remediation="Set-MpPreference -PUAProtection Enabled",
                owner="IT Security",
                source_files=["defender_preferences.txt"],
            ))

    return running, updated, exclusions, findings


def parse_edr(files: Dict[str, str]) -> tuple:
    """Parse edr_candidates_present.txt. Returns (detected, name, findings)."""
    findings = []
    content = files.get("edr_candidates_present.txt", "")

    if not content or not content.strip():
        findings.append(Finding(
            severity="HIGH", category="EDR/XDR",
            title="No EDR/XDR solution detected",
            description="No Endpoint Detection & Response agent found. Machine lacks advanced threat detection.",
            remediation="Deploy organizational EDR solution (CrowdStrike, SentinelOne, MDE, etc.)",
            owner="IT Security",
            attacker_context="No EDR = no behavioral detection. I can use living-off-the-land techniques freely.",
            source_files=["edr_candidates_present.txt"],
        ))
        return False, "", findings

    name = content.strip()
    # Known EDR service names
    edr_map = {
        "sense": "Microsoft Defender for Endpoint",
        "csfalcon": "CrowdStrike Falcon",
        "sentinelagent": "SentinelOne",
        "carbonblack": "VMware Carbon Black",
        "cylance": "Cylance",
        "tanium": "Tanium",
    }

    display_name = name
    for key, val in edr_map.items():
        if key in name.lower():
            display_name = val
            break

    if "no edr" in name.lower() or "not found" in name.lower() or "none" in name.lower():
        findings.append(Finding(
            severity="HIGH", category="EDR/XDR",
            title="No EDR/XDR solution detected",
            description=f"EDR check returned: '{name}'. No endpoint detection & response agent found.",
            remediation="Deploy organizational EDR solution.",
            owner="IT Security",
            attacker_context="No EDR = no behavioral detection.",
            source_files=["edr_candidates_present.txt"],
        ))
        return False, "", findings

    return True, display_name, findings
