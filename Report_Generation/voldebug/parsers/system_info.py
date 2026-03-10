"""Parsers for system information, BIOS, and network configuration."""
import re
from typing import Dict
from ..models import SystemInfo


def parse_os_info(files: Dict[str, str]) -> dict:
    """Parse os_summary.txt and systeminfo.txt for OS details."""
    info = {}

    # os_summary.txt (key : value format)
    os_txt = files.get("os_summary.txt", "")
    if os_txt:
        for line in os_txt.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                k, v = k.strip(), v.strip()
                if "caption" in k.lower():
                    info["os_name"] = v
                elif k.lower() == "version":
                    info["os_version"] = v
                elif "buildnumber" in k.lower():
                    info["build"] = v
                elif "osarchitecture" in k.lower():
                    info["os_arch"] = v
                elif "lastbootuptime" in k.lower():
                    info["last_boot"] = v

    # systeminfo.txt (fallback, different format)
    si = files.get("systeminfo.txt", "")
    if si:
        for line in si.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                k, v = k.strip(), v.strip()
                if "os name" in k.lower() and not info.get("os_name"):
                    info["os_name"] = v
                elif "os version" in k.lower() and not info.get("os_version"):
                    info["os_version"] = v
                elif "system type" in k.lower() and not info.get("os_arch"):
                    info["os_arch"] = v
                elif "system manufacturer" in k.lower():
                    info["manufacturer"] = v
                elif "system model" in k.lower():
                    info["model"] = v
                elif "bios version" in k.lower():
                    info["bios_version"] = v

    return info


def parse_bios(files: Dict[str, str]) -> dict:
    """Parse bios.txt — handles PowerShell table format."""
    info = {}
    bios = files.get("bios.txt", "")
    if not bios:
        return info

    lines = [l.strip() for l in bios.splitlines() if l.strip() and not l.strip().startswith("-")]
    if len(lines) >= 2:
        # PowerShell table: header row then data row
        headers = lines[0].split()
        data_line = lines[1]
        # Split data by column positions from header
        parts = data_line.split()
        header_map = {h.lower(): i for i, h in enumerate(headers)}
        for key, idx in header_map.items():
            if idx < len(parts):
                if "serial" in key:
                    info["serial"] = parts[idx]
                elif "manufacturer" in key:
                    # Manufacturer might be multi-word like "Dell Inc."
                    info["manufacturer"] = " ".join(parts[idx:idx+2]) if idx+1 < len(parts) and not any(k in parts[idx+1].lower() for k in ["serial", "smbios", "version"]) else parts[idx]
                elif "smbios" in key or "version" in key:
                    info["bios_version"] = parts[idx]

    # Also try key:value format
    for line in bios.splitlines():
        if ":" in line or "=" in line:
            sep = ":" if ":" in line else "="
            k, v = line.split(sep, 1)
            k, v = k.strip().lower(), v.strip()
            if "serial" in k:
                info["serial"] = v
            elif "manufacturer" in k or "vendor" in k:
                info["manufacturer"] = v
            elif "product" in k or "model" in k:
                info["model"] = v
            elif "bios" in k and "version" in k:
                info["bios_version"] = v
            elif "last boot" in k or "lastboot" in k:
                info["last_boot"] = v

    return info


def parse_ipconfig(files: Dict[str, str]) -> dict:
    """Parse ipconfig_all.txt for hostname, IP, MAC, domain."""
    info = {}
    ipcfg = files.get("ipconfig_all.txt", "")
    if not ipcfg:
        return info

    for line in ipcfg.splitlines():
        line_stripped = line.strip()
        if ":" not in line_stripped:
            continue

        # Handle dotted labels like "Host Name . . . . . . . : VALUE"
        # Only strip sequences of 2+ dots with surrounding spaces (not single dots in IPs)
        cleaned = re.sub(r'\s+\.(\s*\.)+\s*', ' ', line_stripped)
        if ":" in cleaned:
            k, v = cleaned.split(":", 1)
            k, v = k.strip().lower(), v.strip()

            if "host name" in k and not info.get("hostname"):
                info["hostname"] = v
            elif "primary dns suffix" in k and v:
                info["domain"] = v
            elif "connection-specific dns suffix" in k and v and not info.get("domain"):
                info["domain"] = v
            elif "ipv4 address" in k and not info.get("ip"):
                info["ip"] = re.sub(r'\(.*?\)', '', v).strip()
            elif "physical address" in k and not info.get("mac"):
                mac = v.strip()
                if len(mac) >= 17:
                    info["mac"] = mac
            elif "default gateway" in k and v and not info.get("gateway"):
                # Skip IPv6 gateways
                gw = v.strip()
                if re.match(r'\d+\.\d+\.\d+\.\d+', gw):
                    info["gateway"] = gw

    return info


def build_system_info(files: Dict[str, str]) -> SystemInfo:
    """Build a complete SystemInfo from all available sources."""
    os_data = parse_os_info(files)
    bios_data = parse_bios(files)
    net_data = parse_ipconfig(files)

    # Parse summary.txt for collection metadata
    summary = files.get("summary.txt", "")
    auditor = ""
    collection_time = ""
    for line in summary.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            k, v = k.strip().lower(), v.strip()
            if "auditor" in k:
                auditor = v
            elif "start time" in k:
                collection_time = v

    hostname = net_data.get("hostname", "")
    manufacturer = bios_data.get("manufacturer", os_data.get("manufacturer", ""))
    model = bios_data.get("model", os_data.get("model", ""))

    # Detect portable/laptop
    is_portable = False
    model_lower = model.lower() if model else ""
    mfg_lower = manufacturer.lower() if manufacturer else ""
    if any(kw in model_lower for kw in ["laptop", "notebook", "thinkpad", "latitude", "inspiron", "pavilion", "elitebook", "probook", "vivobook", "zenbook", "surface"]):
        is_portable = True
    elif any(kw in mfg_lower for kw in ["dell", "lenovo", "hp"]) and any(kw in model_lower for kw in ["xps", "precision mobile"]):
        is_portable = True

    # Detect server/admin workstation
    is_server = False
    hostname_lower = hostname.lower()
    if any(kw in hostname_lower for kw in ["admin", "server", "dc-", "dc0", "srv", "sql", "exchange"]):
        is_server = True
    os_name = os_data.get("os_name", "")
    if "server" in os_name.lower():
        is_server = True

    return SystemInfo(
        hostname=hostname,
        ip=net_data.get("ip", ""),
        mac=net_data.get("mac", ""),
        domain=net_data.get("domain", ""),
        os_name=os_name,
        os_version=os_data.get("os_version", ""),
        os_arch=os_data.get("os_arch", ""),
        manufacturer=manufacturer,
        model=model,
        serial=bios_data.get("serial", ""),
        bios_version=bios_data.get("bios_version", os_data.get("bios_version", "")),
        last_boot=bios_data.get("last_boot", os_data.get("last_boot", "")),
        is_portable=is_portable,
        is_server=is_server,
    )
