"""Excel report generator using openpyxl."""
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter
from ..models import MachineAudit, FleetSummary
from typing import List


SEVERITY_COLORS = {
    "CRITICAL": "FF2D55",
    "HIGH": "FF6B35",
    "MEDIUM": "FFB800",
    "LOW": "39FF14",
    "INFO": "888888",
}

HEADER_FILL = PatternFill(start_color="1A1A2E", end_color="1A1A2E", fill_type="solid")
HEADER_FONT = Font(name="Calibri", bold=True, color="00D4FF", size=11)
DATA_FONT = Font(name="Calibri", color="FFFFFF", size=10)
BORDER = Border(
    left=Side(style='thin', color='333355'),
    right=Side(style='thin', color='333355'),
    top=Side(style='thin', color='333355'),
    bottom=Side(style='thin', color='333355'),
)


def generate_fleet_excel(audits: List[MachineAudit], summary: FleetSummary, output_path: str):
    """Generate fleet summary Excel workbook."""
    wb = Workbook()

    # --- Sheet 1: Fleet Summary ---
    ws = wb.active
    ws.title = "Fleet Summary"
    ws.sheet_properties.tabColor = "00D4FF"

    # Header
    headers = ["Hostname", "IP Address", "OS", "Risk Score", "Risk Level",
               "CRITICAL", "HIGH", "MEDIUM", "LOW", "Total Findings",
               "BitLocker", "Defender", "EDR", "Patch Gap (days)", "Local Admins"]

    for col, header in enumerate(headers, 1):
        cell = ws.cell(row=1, column=col, value=header)
        cell.font = HEADER_FONT
        cell.fill = HEADER_FILL
        cell.border = BORDER
        cell.alignment = Alignment(horizontal='center')

    # Data rows
    sorted_audits = sorted(audits, key=lambda a: a.risk_score, reverse=True)
    for row_idx, audit in enumerate(sorted_audits, 2):
        data = [
            audit.hostname,
            audit.system_info.ip,
            audit.system_info.os_name,
            audit.risk_score,
            audit.risk_level,
            audit.critical_count,
            audit.high_count,
            audit.medium_count,
            audit.low_count,
            len(audit.findings),
            "ON" if audit.security_posture.bitlocker_enabled else "OFF",
            "Running" if audit.security_posture.defender_running else "STOPPED",
            audit.security_posture.edr_name or "None",
            audit.patch_gap_days if audit.patch_gap_days >= 0 else "N/A",
            len(audit.local_admins),
        ]
        for col, val in enumerate(data, 1):
            cell = ws.cell(row=row_idx, column=col, value=val)
            cell.font = DATA_FONT
            cell.border = BORDER

            # Color code risk level
            if col == 5 and isinstance(val, str):
                color = SEVERITY_COLORS.get(val.upper(), "888888")
                cell.font = Font(name="Calibri", bold=True, color=color, size=10)

    # Auto-fit columns
    for col in range(1, len(headers) + 1):
        ws.column_dimensions[get_column_letter(col)].width = max(12, len(headers[col - 1]) + 4)

    # --- Sheet 2: All Findings ---
    ws2 = wb.create_sheet("All Findings")
    ws2.sheet_properties.tabColor = "FF2D55"

    finding_headers = ["Machine", "Severity", "Category", "Title", "Description",
                       "Remediation", "Owner", "Compound"]
    for col, header in enumerate(finding_headers, 1):
        cell = ws2.cell(row=1, column=col, value=header)
        cell.font = HEADER_FONT
        cell.fill = HEADER_FILL
        cell.border = BORDER

    row_idx = 2
    for audit in sorted_audits:
        # Sort findings by severity
        sorted_findings = sorted(
            audit.findings,
            key=lambda f: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(f.severity, 5)
        )
        for f in sorted_findings:
            data = [
                audit.hostname, f.severity, f.category, f.title,
                f.description[:500], f.remediation[:300], f.owner,
                "YES" if f.is_compound else ""
            ]
            for col, val in enumerate(data, 1):
                cell = ws2.cell(row=row_idx, column=col, value=val)
                cell.font = DATA_FONT
                cell.border = BORDER
                if col == 2:
                    color = SEVERITY_COLORS.get(f.severity, "888888")
                    cell.font = Font(name="Calibri", bold=True, color=color, size=10)
            row_idx += 1

    # Column widths
    widths = [25, 10, 15, 40, 60, 50, 15, 10]
    for col, w in enumerate(widths, 1):
        ws2.column_dimensions[get_column_letter(col)].width = w

    # --- Sheet 3: Remediation Plan ---
    ws3 = wb.create_sheet("Remediation Plan")
    ws3.sheet_properties.tabColor = "39FF14"

    rem_headers = ["Priority", "Machine", "Severity", "Finding", "Command", "Owner"]
    for col, header in enumerate(rem_headers, 1):
        cell = ws3.cell(row=1, column=col, value=header)
        cell.font = HEADER_FONT
        cell.fill = HEADER_FILL
        cell.border = BORDER

    row_idx = 2
    priority = 1
    for audit in sorted_audits:
        critical_high = [f for f in audit.findings
                         if f.severity in ("CRITICAL", "HIGH") and f.remediation]
        critical_high.sort(key=lambda f: 0 if f.severity == "CRITICAL" else 1)
        for f in critical_high:
            data = [priority, audit.hostname, f.severity, f.title, f.remediation, f.owner]
            for col, val in enumerate(data, 1):
                cell = ws3.cell(row=row_idx, column=col, value=val)
                cell.font = DATA_FONT
                cell.border = BORDER
            row_idx += 1
            priority += 1

    widths3 = [8, 25, 10, 40, 60, 15]
    for col, w in enumerate(widths3, 1):
        ws3.column_dimensions[get_column_letter(col)].width = w

    wb.save(output_path)
    return output_path
