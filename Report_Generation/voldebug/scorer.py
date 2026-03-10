"""Risk scoring with severity caps and multipliers per system prompt spec.

Scoring model:
  CRITICAL → +35 pts (cap at 2 = 70 max)
  HIGH     → +20 pts (cap at 3 = 60 max)
  MEDIUM   → +10 pts (cap at 5 = 50 max)
  LOW      → +3 pts  (no cap)

Multipliers:
  × 1.3 if no EDR AND no Defender (blind machine)
  × 1.2 if CRITICAL security events detected
  × 1.1 if hostname contains ADMIN, SERVER, DC, SRV
"""
from .models import MachineAudit


SEVERITY_POINTS = {"CRITICAL": 35, "HIGH": 20, "MEDIUM": 10, "LOW": 3, "INFO": 0}
SEVERITY_CAPS = {"CRITICAL": 2, "HIGH": 3, "MEDIUM": 5}


def calculate_risk_score(audit: MachineAudit) -> tuple:
    """Calculate risk score (0-100) and risk level.

    Returns (score, level_string).
    """
    # Count findings by severity (respecting caps)
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in audit.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    # Calculate base score with caps
    score = 0
    for sev, pts in SEVERITY_POINTS.items():
        count = counts.get(sev, 0)
        cap = SEVERITY_CAPS.get(sev, count)  # No cap for LOW and INFO
        effective = min(count, cap)
        score += effective * pts

    # Apply multipliers
    multiplier = 1.0

    # Blind machine: no EDR AND no Defender
    sp = audit.security_posture
    if not sp.edr_detected and sp.defender_running is False:
        multiplier *= 1.3

    # Critical security events
    es = audit.event_summary
    if es.log_cleared > 0 or es.defender_rtp_disabled > 0:
        multiplier *= 1.2

    # Admin/server workstation
    hostname = audit.system_info.hostname.lower()
    if any(kw in hostname for kw in ["admin", "server", "dc-", "dc0", "srv", "sql", "exchange"]):
        multiplier *= 1.1

    # Server OS
    if audit.system_info.is_server:
        multiplier *= 1.1

    # Apply multiplier and cap at 100
    final_score = min(100, round(score * multiplier))

    # Determine risk level
    if final_score >= 70:
        level = "Critical"
    elif final_score >= 40:
        level = "High"
    elif final_score >= 20:
        level = "Medium"
    else:
        level = "Low"

    return final_score, level
