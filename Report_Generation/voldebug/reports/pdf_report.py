"""Professional PDF report generator using ReportLab + matplotlib.

Produces enterprise-grade PDF reports with:
- Dark cover page with risk score bar
- Executive summary with security posture cards
- Risk dashboard with charts (donut, category bars, radar)
- Color-coded findings table
- Remediation plan
- Fleet summary with heatmap

All generated in-memory via BytesIO (no temp files).
"""
import io
import math
from datetime import datetime
from typing import List, Optional
from collections import Counter

import matplotlib
matplotlib.use("Agg")
import warnings
warnings.filterwarnings("ignore", message="posx and posy should be finite values")
import matplotlib.pyplot as plt
import numpy as np

from reportlab.lib.pagesizes import A4
from reportlab.lib.colors import HexColor
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    Image as RLImage, PageBreak, KeepTogether,
)
from reportlab.platypus.flowables import Flowable
from reportlab.pdfgen import canvas as pdfcanvas

from ..models import MachineAudit, FleetSummary


# ═══════════════════════════════════════════════════
# DESIGN SYSTEM
# ═══════════════════════════════════════════════════

PAGE_W, PAGE_H = A4
MARGIN_LEFT = 45
MARGIN_RIGHT = 45
MARGIN_TOP = 50
MARGIN_BOTTOM = 50
CONTENT_W = PAGE_W - MARGIN_LEFT - MARGIN_RIGHT

# Colors
COLOR_BG_DARK = HexColor('#0F1923')
COLOR_BG_PANEL = HexColor('#FFFFFF')
COLOR_BG_SUBTLE = HexColor('#F1F5F9')
COLOR_ACCENT = HexColor('#0EA5E9')
COLOR_ACCENT_DARK = HexColor('#0369A1')
COLOR_CRITICAL = HexColor('#DC2626')
COLOR_HIGH = HexColor('#EA580C')
COLOR_MEDIUM = HexColor('#D97706')
COLOR_LOW = HexColor('#16A34A')
COLOR_INFO = HexColor('#6366F1')
COLOR_TEXT_PRIMARY = HexColor('#0F172A')
COLOR_TEXT_SECONDARY = HexColor('#475569')
COLOR_TEXT_MUTED = HexColor('#94A3B8')
COLOR_WHITE = HexColor('#FFFFFF')
COLOR_BORDER = HexColor('#E2E8F0')

SEV_COLORS = {
    'CRITICAL': COLOR_CRITICAL, 'HIGH': COLOR_HIGH,
    'MEDIUM': COLOR_MEDIUM, 'LOW': COLOR_LOW, 'INFO': COLOR_INFO,
}
SEV_BG = {
    'CRITICAL': HexColor('#FEF2F2'), 'HIGH': HexColor('#FFF7ED'),
    'MEDIUM': HexColor('#FFFBEB'), 'LOW': HexColor('#F0FDF4'),
    'INFO': HexColor('#EEF2FF'),
}


def severity_color(level: str):
    l = level.upper() if level else ""
    if "CRIT" in l: return COLOR_CRITICAL
    if "HIGH" in l: return COLOR_HIGH
    if "MED" in l: return COLOR_MEDIUM
    if "LOW" in l: return COLOR_LOW
    return COLOR_INFO


# Styles
STYLE_SECTION = ParagraphStyle('Section', fontName='Helvetica-Bold', fontSize=13,
    leading=18, textColor=COLOR_ACCENT_DARK, spaceBefore=18, spaceAfter=8)
STYLE_BODY = ParagraphStyle('Body', fontName='Helvetica', fontSize=9,
    leading=14, textColor=COLOR_TEXT_PRIMARY, spaceAfter=6)
STYLE_SMALL = ParagraphStyle('Small', fontName='Helvetica', fontSize=8,
    leading=12, textColor=COLOR_TEXT_SECONDARY)
STYLE_CAPTION = ParagraphStyle('Caption', fontName='Helvetica-Oblique', fontSize=8,
    textColor=COLOR_TEXT_MUTED, alignment=TA_CENTER)


# ═══════════════════════════════════════════════════
# MATPLOTLIB CHARTS (white background, professional)
# ═══════════════════════════════════════════════════

def _fig_to_bytesio(fig) -> io.BytesIO:
    buf = io.BytesIO()
    fig.savefig(buf, format='png', dpi=150, bbox_inches='tight',
                facecolor='white', edgecolor='none')
    plt.close(fig)
    buf.seek(0)
    return buf


def make_severity_donut(findings: list) -> io.BytesIO:
    counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for f in findings:
        sev = f.severity if hasattr(f, 'severity') else f.get('severity', 'INFO')
        if sev in counts:
            counts[sev] += 1

    sizes = list(counts.values())
    colors = ['#DC2626', '#EA580C', '#D97706', '#16A34A']
    total = sum(sizes)

    fig, ax = plt.subplots(figsize=(4, 4), facecolor='white')
    if total == 0:
        ax.text(0.5, 0.5, 'No Findings', ha='center', va='center',
                fontsize=12, color='#94A3B8', transform=ax.transAxes)
        ax.axis('off')
    else:
        wedges, _ = ax.pie(
            sizes, colors=colors, startangle=90,
            wedgeprops=dict(width=0.55, edgecolor='white', linewidth=2),
        )
        ax.text(0, 0.08, str(total), ha='center', va='center',
                fontsize=28, fontweight='bold', color='#0F172A')
        ax.text(0, -0.18, 'TOTAL\nFINDINGS', ha='center', va='center',
                fontsize=7, color='#94A3B8', linespacing=1.4)

    # Legend
    for i, (sev, cnt) in enumerate(counts.items()):
        ax.plot([], [], 's', color=colors[i], markersize=8,
                label=f'{sev}: {cnt}')
    ax.legend(loc='lower center', bbox_to_anchor=(0.5, -0.15), ncol=4,
              fontsize=7, frameon=False, handletextpad=0.3, columnspacing=1)

    ax.set_title('Findings by Severity', fontsize=10, fontweight='bold',
                 color='#0F172A', pad=10)
    ax.axis('equal')
    return _fig_to_bytesio(fig)


def make_category_bar(findings: list) -> Optional[io.BytesIO]:
    categories = Counter()
    for f in findings:
        cat = f.category if hasattr(f, 'category') else f.get('category', 'Other')
        categories[cat] += 1
    if not categories:
        return None

    sorted_items = sorted(categories.items(), key=lambda x: x[1])
    cats = [c[0] for c in sorted_items]
    vals = [c[1] for c in sorted_items]
    max_val = max(vals) if vals else 1

    fig, ax = plt.subplots(figsize=(5, max(3, len(cats) * 0.5 + 1)),
                           facecolor='white')
    bar_colors = ['#DC2626' if v == max_val else '#0EA5E9' for v in vals]
    bars = ax.barh(cats, vals, color=bar_colors, height=0.55, edgecolor='none')

    ax.set_xlabel('Number of Findings', fontsize=8, color='#64748B')
    ax.set_title('Findings by Category', fontsize=10, fontweight='bold',
                 color='#0F172A', pad=10)
    ax.tick_params(axis='y', labelsize=8, colors='#475569')
    ax.tick_params(axis='x', labelsize=7, colors='#94A3B8')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_color('#E2E8F0')
    ax.spines['bottom'].set_color('#E2E8F0')
    ax.set_facecolor('white')

    for bar, val in zip(bars, vals):
        ax.text(bar.get_width() + 0.15, bar.get_y() + bar.get_height() / 2,
                str(val), va='center', fontsize=8, color='#0F172A', fontweight='bold')

    plt.tight_layout()
    return _fig_to_bytesio(fig)


def make_radar_chart(audit: MachineAudit) -> io.BytesIO:
    sp = audit.security_posture
    categories = ['Encryption', 'Antivirus', 'EDR', 'Firewall',
                  'Patch Level', 'Privilege\nControl', 'Credential\nSecurity']

    patch_score = max(0, 10 - (audit.patch_gap_days / 10)) if audit.patch_gap_days >= 0 else 5
    admin_score = max(0, 10 - (len(audit.local_admins) - 2) * 2)
    cred_score = max(0, 10 - len(audit.stored_credentials) * 3)
    fw_score = sum([
        1 if sp.firewall_domain else 0,
        1 if sp.firewall_private else 0,
        1 if sp.firewall_public else 0,
    ]) * 3.33

    scores = [
        10 if sp.bitlocker_enabled else 0,
        10 if sp.defender_running and sp.defender_updated else (5 if sp.defender_running else 0),
        10 if sp.edr_detected else 0,
        round(fw_score, 1),
        round(patch_score, 1),
        round(admin_score, 1),
        round(cred_score, 1),
    ]

    N = len(categories)
    angles = [n / float(N) * 2 * math.pi for n in range(N)]
    angles += angles[:1]
    scores_closed = scores + scores[:1]

    fig, ax = plt.subplots(figsize=(4, 4), subplot_kw=dict(polar=True),
                           facecolor='white')
    ax.fill(angles, scores_closed, color='#0EA5E9', alpha=0.15)
    ax.plot(angles, scores_closed, color='#0EA5E9', linewidth=2, marker='o',
            markersize=4, markerfacecolor='#0EA5E9')

    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(categories, size=7, color='#475569')
    ax.set_ylim(0, 10)
    ax.set_yticks([2, 4, 6, 8, 10])
    ax.set_yticklabels(['2', '4', '6', '8', '10'], size=6, color='#94A3B8')
    ax.grid(color='#E2E8F0', linewidth=0.8)
    ax.spines['polar'].set_color('#E2E8F0')
    ax.set_facecolor('white')
    ax.set_title('Security Controls Coverage', fontsize=10,
                 fontweight='bold', color='#0F172A', pad=15)

    plt.tight_layout()
    return _fig_to_bytesio(fig)


def make_fleet_risk_bar(audits: List[MachineAudit]) -> io.BytesIO:
    sorted_a = sorted(audits, key=lambda a: a.risk_score, reverse=True)[:20]
    names = [a.hostname[:18] for a in sorted_a]
    scores = [a.risk_score for a in sorted_a]
    colors_list = [
        '#DC2626' if s >= 70 else '#EA580C' if s >= 45 else '#D97706' if s >= 20 else '#16A34A'
        for s in scores
    ]

    fig, ax = plt.subplots(figsize=(7, max(3, len(names) * 0.45 + 1)),
                           facecolor='white')
    bars = ax.barh(range(len(names)), scores, color=colors_list, height=0.55, edgecolor='none')
    ax.set_yticks(range(len(names)))
    ax.set_yticklabels(names, fontsize=8, color='#475569')
    ax.invert_yaxis()
    ax.axvline(x=70, color='#DC2626', linestyle='--', linewidth=1, alpha=0.4)
    ax.axvline(x=45, color='#D97706', linestyle='--', linewidth=1, alpha=0.4)
    ax.set_xlim(0, 105)
    ax.set_xlabel('Risk Score', fontsize=8, color='#64748B')
    ax.set_title('Machine Risk Scores', fontsize=11, fontweight='bold',
                 color='#0F172A', pad=12)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_color('#E2E8F0')
    ax.spines['bottom'].set_color('#E2E8F0')
    ax.set_facecolor('white')

    for bar, val in zip(bars, scores):
        ax.text(bar.get_width() + 1, bar.get_y() + bar.get_height() / 2,
                str(val), va='center', fontsize=8, color='#0F172A', fontweight='bold')

    plt.tight_layout()
    return _fig_to_bytesio(fig)


def make_controls_heatmap(audits: List[MachineAudit]) -> io.BytesIO:
    controls = ['BitLocker', 'Defender', 'EDR', 'FW Domain', 'FW Private', 'FW Public']
    data = []
    labels = []
    for a in sorted(audits, key=lambda x: x.risk_score, reverse=True)[:15]:
        sp = a.security_posture
        row = [
            1 if sp.bitlocker_enabled else 0,
            1 if sp.defender_running else 0,
            1 if sp.edr_detected else 0,
            1 if sp.firewall_domain else 0,
            1 if sp.firewall_private else 0,
            1 if sp.firewall_public else 0,
        ]
        data.append(row)
        labels.append(a.hostname[:16])

    data_arr = np.array(data) if data else np.array([[0]*6])
    if not labels:
        labels = ["N/A"]

    fig, ax = plt.subplots(figsize=(7, max(2.5, len(labels) * 0.45 + 1)),
                           facecolor='white')
    cmap = plt.cm.RdYlGn
    ax.imshow(data_arr, cmap=cmap, aspect='auto', vmin=0, vmax=1)

    ax.set_xticks(range(len(controls)))
    ax.set_xticklabels(controls, fontsize=8, color='#475569')
    ax.set_yticks(range(len(labels)))
    ax.set_yticklabels(labels, fontsize=7, color='#475569')

    for i in range(len(labels)):
        for j in range(len(controls)):
            val = data_arr[i, j] if i < data_arr.shape[0] else 0
            text = 'Y' if val == 1 else 'N'
            color = '#166534' if val == 1 else '#991B1B'
            ax.text(j, i, text, ha='center', va='center', fontsize=9,
                    fontweight='bold', color=color)

    ax.set_title('Security Controls Coverage', fontsize=10,
                 fontweight='bold', color='#0F172A', pad=10)
    plt.tight_layout()
    return _fig_to_bytesio(fig)


def _draw_machine_cover(canvas_obj, doc):
    """Draw the dark cover page directly on the canvas (page 1)."""
    a = doc._audit_data
    c = canvas_obj
    w, h = PAGE_W, PAGE_H
    sinfo = a.system_info

    # Dark background
    c.setFillColor(COLOR_BG_DARK)
    c.rect(0, 0, w, h, fill=1, stroke=0)

    # Accent top bar
    c.setFillColor(COLOR_ACCENT)
    c.rect(MARGIN_LEFT, h - 80, CONTENT_W * 0.75, 4, fill=1, stroke=0)

    # Brand label
    c.setFillColor(COLOR_ACCENT)
    c.setFont('Helvetica-Bold', 9)
    c.drawString(MARGIN_LEFT, h - 65, 'VOLDEBUG AUDIT INTELLIGENCE SYSTEM')

    # Main title
    c.setFillColor(COLOR_WHITE)
    c.setFont('Helvetica-Bold', 34)
    c.drawString(MARGIN_LEFT, h - 140, 'SECURITY')
    c.drawString(MARGIN_LEFT, h - 178, 'AUDIT REPORT')

    # Hostname
    c.setFont('Helvetica-Bold', 18)
    c.setFillColor(COLOR_ACCENT)
    c.drawString(MARGIN_LEFT, h - 230, sinfo.hostname or a.folder_name)

    # IP / Domain
    c.setFont('Helvetica', 10)
    c.setFillColor(HexColor('#94A3B8'))
    subtitle = f"{sinfo.ip or 'Unknown IP'}  |  {sinfo.domain or 'WORKGROUP'}"
    c.drawString(MARGIN_LEFT, h - 250, subtitle)

    # Divider
    c.setStrokeColor(HexColor('#1E3A5F'))
    c.setLineWidth(1)
    c.line(MARGIN_LEFT, h - 268, w - MARGIN_RIGHT, h - 268)

    # Dates
    c.setFont('Helvetica', 9)
    c.setFillColor(HexColor('#64748B'))
    c.drawString(MARGIN_LEFT, h - 290, f"Collection Date:   {a.collection_time or 'N/A'}")
    c.drawString(MARGIN_LEFT, h - 306, f"Report Generated:  {a.analyzed_at[:19] if a.analyzed_at else 'N/A'}")
    if a.auditor:
        c.drawString(MARGIN_LEFT, h - 322, f"Auditor:           {a.auditor}")

    # Risk score box
    box_y = h - 460
    box_h = 115
    c.setFillColor(HexColor('#141F2E'))
    c.roundRect(MARGIN_LEFT, box_y, CONTENT_W, box_h, 8, fill=1, stroke=0)
    sc = severity_color(a.risk_level)
    c.setStrokeColor(sc)
    c.setLineWidth(1.5)
    c.roundRect(MARGIN_LEFT, box_y, CONTENT_W, box_h, 8, fill=0, stroke=1)

    # Risk score number
    c.setFont('Helvetica-Bold', 46)
    c.setFillColor(sc)
    c.drawString(MARGIN_LEFT + 22, box_y + 58, str(a.risk_score))
    c.setFont('Helvetica', 11)
    c.setFillColor(HexColor('#94A3B8'))
    c.drawString(MARGIN_LEFT + 22, box_y + 40, '/ 100  RISK SCORE')
    c.setFont('Helvetica-Bold', 11)
    c.setFillColor(sc)
    c.drawString(MARGIN_LEFT + 22, box_y + 18, f"{a.risk_level.upper()} RISK")

    # Risk bar
    bar_x = MARGIN_LEFT + 160
    bar_y = box_y + 62
    bar_w = CONTENT_W - 180
    bar_h_px = 16
    c.setFillColor(HexColor('#1E3A5F'))
    c.roundRect(bar_x, bar_y, bar_w, bar_h_px, 4, fill=1, stroke=0)
    fill_w = max(4, bar_w * (a.risk_score / 100))
    c.setFillColor(sc)
    c.roundRect(bar_x, bar_y, fill_w, bar_h_px, 4, fill=1, stroke=0)

    # Severity counts
    sev_items = [
        ('CRITICAL', a.critical_count, COLOR_CRITICAL),
        ('HIGH', a.high_count, COLOR_HIGH),
        ('MEDIUM', a.medium_count, COLOR_MEDIUM),
        ('LOW', a.low_count, COLOR_LOW),
    ]
    sx = bar_x
    for sev_name, cnt, col in sev_items:
        c.setFillColor(col)
        c.circle(sx + 5, box_y + 28, 4, fill=1, stroke=0)
        c.setFont('Helvetica-Bold', 9)
        c.setFillColor(COLOR_WHITE)
        c.drawString(sx + 14, box_y + 24, f"{cnt} {sev_name}")
        sx += (CONTENT_W - 180) / 4

    # Total findings
    c.setFont('Helvetica', 9)
    c.setFillColor(HexColor('#64748B'))
    c.drawString(bar_x, box_y + 5,
                 f"Total: {len(a.findings)} finding(s)  |  Files analyzed: {a.file_count}")

    # Footer bar
    c.setFillColor(HexColor('#0A1420'))
    c.rect(0, 0, w, 42, fill=1, stroke=0)
    c.setFont('Helvetica', 8)
    c.setFillColor(HexColor('#475569'))
    c.drawString(MARGIN_LEFT, 16, 'VOLDEBUG Audit Intelligence System v1.0')
    c.setFillColor(COLOR_CRITICAL)
    c.drawRightString(w - MARGIN_RIGHT, 16, 'CONFIDENTIAL - INTERNAL USE ONLY')


def _draw_fleet_cover(canvas_obj, doc):
    """Draw fleet cover page directly on canvas (page 1)."""
    s = doc._fleet_summary
    c = canvas_obj
    w, h = PAGE_W, PAGE_H

    c.setFillColor(COLOR_BG_DARK)
    c.rect(0, 0, w, h, fill=1, stroke=0)

    c.setFillColor(COLOR_ACCENT)
    c.rect(MARGIN_LEFT, h - 80, CONTENT_W * 0.75, 4, fill=1, stroke=0)

    c.setFillColor(COLOR_ACCENT)
    c.setFont('Helvetica-Bold', 9)
    c.drawString(MARGIN_LEFT, h - 65, 'VOLDEBUG AUDIT INTELLIGENCE SYSTEM')

    c.setFillColor(COLOR_WHITE)
    c.setFont('Helvetica-Bold', 34)
    c.drawString(MARGIN_LEFT, h - 140, 'FLEET SECURITY')
    c.drawString(MARGIN_LEFT, h - 178, 'AUDIT REPORT')

    c.setFont('Helvetica', 11)
    c.setFillColor(HexColor('#94A3B8'))
    c.drawString(MARGIN_LEFT, h - 210,
                 f"{s.total_machines} Machine(s)  |  Generated: {s.generated_at[:19]}")

    c.setStrokeColor(HexColor('#1E3A5F'))
    c.line(MARGIN_LEFT, h - 230, w - MARGIN_RIGHT, h - 230)

    # Risk level cards
    items = [
        (f"{s.critical_machines}", "CRITICAL", COLOR_CRITICAL),
        (f"{s.high_machines}", "HIGH", COLOR_HIGH),
        (f"{s.medium_machines}", "MEDIUM", COLOR_MEDIUM),
        (f"{s.low_machines}", "LOW", COLOR_LOW),
    ]
    card_w = (CONTENT_W - 30) / 4
    cx = MARGIN_LEFT
    for val, label, col in items:
        c.setFillColor(HexColor('#141F2E'))
        c.roundRect(cx, h - 340, card_w, 80, 6, fill=1, stroke=0)
        c.setStrokeColor(col)
        c.setLineWidth(1)
        c.roundRect(cx, h - 340, card_w, 80, 6, fill=0, stroke=1)
        c.setFont('Helvetica-Bold', 28)
        c.setFillColor(col)
        c.drawCentredString(cx + card_w / 2, h - 305, val)
        c.setFont('Helvetica', 8)
        c.setFillColor(HexColor('#94A3B8'))
        c.drawCentredString(cx + card_w / 2, h - 330, f"{label} RISK")
        cx += card_w + 10

    # Footer
    c.setFillColor(HexColor('#0A1420'))
    c.rect(0, 0, w, 42, fill=1, stroke=0)
    c.setFont('Helvetica', 8)
    c.setFillColor(HexColor('#475569'))
    c.drawString(MARGIN_LEFT, 16, 'VOLDEBUG Audit Intelligence System v1.0')
    c.setFillColor(COLOR_CRITICAL)
    c.drawRightString(w - MARGIN_RIGHT, 16, 'CONFIDENTIAL - INTERNAL USE ONLY')


# ═══════════════════════════════════════════════════
# HEADER / FOOTER CALLBACKS
# ═══════════════════════════════════════════════════

def _header_footer(canvas_obj, doc):
    """Add headers and footers to non-cover pages."""
    c = canvas_obj
    page = doc.page
    if page <= 1:
        return

    w, h = PAGE_W, PAGE_H
    hostname = getattr(doc, '_hostname', '')
    report_date = getattr(doc, '_report_date', '')

    # Header
    c.setStrokeColor(COLOR_BORDER)
    c.setLineWidth(0.5)
    c.line(MARGIN_LEFT, h - 30, w - MARGIN_RIGHT, h - 30)
    c.setFont('Helvetica', 7)
    c.setFillColor(COLOR_TEXT_MUTED)
    c.drawString(MARGIN_LEFT, h - 22, 'VOLDEBUG AUDIT INTELLIGENCE SYSTEM')
    c.drawRightString(w - MARGIN_RIGHT, h - 22, hostname)

    # Footer
    c.line(MARGIN_LEFT, 35, w - MARGIN_RIGHT, 35)
    c.setFont('Helvetica', 7)
    c.setFillColor(COLOR_TEXT_MUTED)
    c.drawString(MARGIN_LEFT, 22, f'Generated: {report_date}')
    c.drawCentredString(w / 2, 22, f'Page {page}')
    c.setFillColor(COLOR_CRITICAL)
    c.drawRightString(w - MARGIN_RIGHT, 22, 'CONFIDENTIAL')


# ═══════════════════════════════════════════════════
# STORY BUILDERS (per-machine)
# ═══════════════════════════════════════════════════

def _build_executive_summary(audit: MachineAudit) -> list:
    """Page 2: Executive summary + posture + system info."""
    story = []
    sinfo = audit.system_info
    sp = audit.security_posture

    story.append(Paragraph('EXECUTIVE SUMMARY', STYLE_SECTION))

    # Summary text
    risk_desc = {
        'Critical': 'is in a CRITICAL security state requiring immediate intervention',
        'High': 'has significant security gaps requiring urgent attention',
        'Medium': 'has moderate security issues that should be addressed',
        'Low': 'is in a generally healthy security state with minor improvements needed',
    }
    desc = risk_desc.get(audit.risk_level, 'has been analyzed')
    compound_count = sum(1 for f in audit.findings if f.is_compound)
    summary_text = (
        f"Machine <b>{sinfo.hostname}</b> {desc}. "
        f"The analysis identified <b>{len(audit.findings)} security finding(s)</b> "
        f"({audit.critical_count} Critical, {audit.high_count} High, "
        f"{audit.medium_count} Medium, {audit.low_count} Low) "
        f"resulting in a risk score of <b>{audit.risk_score}/100</b>."
    )
    if compound_count:
        summary_text += (
            f" <b>{compound_count} compound risk pattern(s)</b> were detected, "
            f"indicating correlated security weaknesses."
        )
    story.append(Paragraph(summary_text, STYLE_BODY))
    story.append(Spacer(1, 12))

    # Security posture table
    story.append(Paragraph('SECURITY POSTURE', STYLE_SECTION))

    def status_text(val, true_t='ENABLED', false_t='DISABLED', none_t='UNKNOWN'):
        if val is True: return true_t
        if val is False: return false_t
        return none_t

    def status_style(val):
        if val is True:
            return ParagraphStyle('g', fontName='Helvetica-Bold', fontSize=9,
                                   textColor=COLOR_LOW, leading=12)
        if val is False:
            return ParagraphStyle('r', fontName='Helvetica-Bold', fontSize=9,
                                   textColor=COLOR_CRITICAL, leading=12)
        return ParagraphStyle('u', fontName='Helvetica-Bold', fontSize=9,
                               textColor=COLOR_TEXT_MUTED, leading=12)

    posture_items = [
        ('BitLocker', sp.bitlocker_enabled),
        ('Defender', sp.defender_running),
        ('EDR/XDR', sp.edr_detected),
        ('FW Domain', sp.firewall_domain),
        ('FW Private', sp.firewall_private),
        ('FW Public', sp.firewall_public),
    ]

    posture_data = []
    row = []
    for i, (label, val) in enumerate(posture_items):
        cell = [
            Paragraph(f'<font size="7" color="#94A3B8">{label.upper()}</font>',
                     ParagraphStyle('l', fontSize=7, leading=10)),
            Paragraph(status_text(val), status_style(val)),
        ]
        row.append(cell)
        if len(row) == 3 or i == len(posture_items) - 1:
            while len(row) < 3:
                row.append('')
            posture_data.append(row)
            row = []

    if posture_data:
        card_w = CONTENT_W / 3 - 4
        posture_table = Table(posture_data, colWidths=[card_w] * 3)
        posture_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), COLOR_BG_PANEL),
            ('BOX', (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(posture_table)

    if sp.edr_detected and sp.edr_name:
        story.append(Paragraph(f'<font color="#475569">EDR Agent: </font>'
                               f'<b>{sp.edr_name}</b>', STYLE_SMALL))

    story.append(Spacer(1, 14))

    # System info table
    story.append(Paragraph('SYSTEM INFORMATION', STYLE_SECTION))
    info_data = [
        ['Hostname', sinfo.hostname, 'IP Address', sinfo.ip],
        ['MAC Address', sinfo.mac, 'Domain', sinfo.domain or 'WORKGROUP'],
        ['OS', f'{sinfo.os_name} {sinfo.os_version}', 'Architecture', sinfo.os_arch],
        ['Manufacturer', sinfo.manufacturer, 'Model', sinfo.model],
        ['Serial', sinfo.serial, 'BIOS', sinfo.bios_version],
        ['Last Boot', sinfo.last_boot, 'Patch Gap', f'{audit.patch_gap_days}d' if audit.patch_gap_days >= 0 else 'Unknown'],
        ['Local Admins', str(len(audit.local_admins)), 'Stored Creds', str(len(audit.stored_credentials))],
        ['Files Collected', str(audit.file_count), 'Collection', audit.collection_time or 'N/A'],
    ]

    # Format into styled table
    styled_data = []
    for row in info_data:
        styled_row = []
        for j, cell in enumerate(row):
            if j % 2 == 0:  # Label
                styled_row.append(Paragraph(
                    f'<font color="#94A3B8" size="7">{cell}</font>',
                    ParagraphStyle('label', fontSize=7, leading=10)))
            else:  # Value
                styled_row.append(Paragraph(
                    f'<b>{cell}</b>',
                    ParagraphStyle('val', fontName='Helvetica-Bold', fontSize=9,
                                   leading=12, textColor=COLOR_TEXT_PRIMARY)))
        styled_data.append(styled_row)

    info_table = Table(styled_data, colWidths=[80, CONTENT_W / 2 - 82, 80, CONTENT_W / 2 - 82])
    info_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), COLOR_BG_PANEL),
        ('ROWBACKGROUNDS', (0, 0), (-1, -1), [COLOR_BG_PANEL, COLOR_BG_SUBTLE]),
        ('LINEBELOW', (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ('BOX', (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(info_table)

    return story


def _build_charts_page(audit: MachineAudit) -> list:
    """Page 3: Risk dashboard with charts."""
    story = []
    story.append(PageBreak())
    story.append(Paragraph('RISK DASHBOARD', STYLE_SECTION))
    story.append(Spacer(1, 6))

    # Row 1: Donut + Radar
    donut_buf = make_severity_donut(audit.findings)
    radar_buf = make_radar_chart(audit)

    chart_w = CONTENT_W / 2 - 8
    chart_h = 210
    row1 = Table(
        [[RLImage(donut_buf, width=chart_w, height=chart_h),
          RLImage(radar_buf, width=chart_w, height=chart_h)]],
        colWidths=[chart_w + 4, chart_w + 4],
    )
    row1.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 2),
        ('RIGHTPADDING', (0, 0), (-1, -1), 2),
    ]))
    story.append(row1)
    story.append(Spacer(1, 10))

    # Row 2: Category bar (full width)
    cat_buf = make_category_bar(audit.findings)
    if cat_buf:
        story.append(RLImage(cat_buf, width=CONTENT_W, height=200))

    return story


def _build_findings_table(audit: MachineAudit) -> list:
    """Page 4: Detailed findings table."""
    story = []
    story.append(PageBreak())
    story.append(Paragraph('DETAILED FINDINGS', STYLE_SECTION))
    story.append(Spacer(1, 6))

    if not audit.findings:
        story.append(Paragraph('No security findings detected.', STYLE_BODY))
        return story

    # Header
    header = [
        Paragraph('<b>#</b>', ParagraphStyle('h', fontName='Helvetica-Bold',
                   fontSize=7, textColor=COLOR_WHITE)),
        Paragraph('<b>SEV</b>', ParagraphStyle('h', fontName='Helvetica-Bold',
                   fontSize=7, textColor=COLOR_WHITE)),
        Paragraph('<b>CATEGORY</b>', ParagraphStyle('h', fontName='Helvetica-Bold',
                   fontSize=7, textColor=COLOR_WHITE)),
        Paragraph('<b>FINDING</b>', ParagraphStyle('h', fontName='Helvetica-Bold',
                   fontSize=7, textColor=COLOR_WHITE)),
    ]
    data = [header]

    sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
    sorted_findings = sorted(audit.findings,
        key=lambda f: sev_order.get(f.severity, 5))

    for i, f in enumerate(sorted_findings, 1):
        sc = SEV_COLORS.get(f.severity, COLOR_INFO)
        compound = '[COMPOUND] ' if f.is_compound else ''

        desc_text = f'<b>{compound}{f.title}</b><br/>'
        desc_text += f'<font size="7" color="#475569">{f.description[:280]}</font>'
        if f.remediation:
            desc_text += f'<br/><font size="7" color="#16A34A">FIX: {f.remediation[:180]}</font>'
        if f.attacker_context:
            desc_text += f'<br/><font size="7" color="#EA580C">{f.attacker_context[:150]}</font>'

        row = [
            Paragraph(str(i).zfill(2), ParagraphStyle('n', fontSize=7,
                      textColor=COLOR_TEXT_SECONDARY)),
            Paragraph(f'<b>{f.severity}</b>', ParagraphStyle('s',
                      fontName='Helvetica-Bold', fontSize=8, textColor=sc)),
            Paragraph(f.category, ParagraphStyle('c', fontSize=7,
                      textColor=COLOR_TEXT_SECONDARY, leading=10)),
            Paragraph(desc_text, ParagraphStyle('d', fontSize=8,
                      leading=11, textColor=COLOR_TEXT_PRIMARY)),
        ]
        data.append(row)

    col_widths = [22, 55, 75, CONTENT_W - 152]
    table = Table(data, colWidths=col_widths, repeatRows=1)

    style_cmds = [
        ('BACKGROUND', (0, 0), (-1, 0), COLOR_BG_DARK),
        ('TEXTCOLOR', (0, 0), (-1, 0), COLOR_WHITE),
        ('TOPPADDING', (0, 0), (-1, 0), 8),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 1), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LINEBELOW', (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ('BOX', (0, 0), (-1, -1), 1, COLOR_BORDER),
    ]

    # Alternating row colors
    for i in range(1, len(data)):
        bg = COLOR_BG_PANEL if i % 2 == 1 else COLOR_BG_SUBTLE
        style_cmds.append(('BACKGROUND', (0, i), (-1, i), bg))

    table.setStyle(TableStyle(style_cmds))
    story.append(table)

    return story


def _build_remediation_plan(audit: MachineAudit) -> list:
    """Page 5: Prioritized remediation plan."""
    rem_findings = [f for f in audit.findings if f.remediation and f.severity in ('CRITICAL', 'HIGH', 'MEDIUM')]
    if not rem_findings:
        return []

    story = []
    story.append(PageBreak())
    story.append(Paragraph('REMEDIATION PLAN', STYLE_SECTION))
    story.append(Paragraph(
        'Priority actions ordered by severity. Execute Critical items within 24 hours.',
        STYLE_SMALL))
    story.append(Spacer(1, 8))

    deadline_map = {'CRITICAL': 'Immediate (24h)', 'HIGH': 'Within 7 days', 'MEDIUM': 'Within 30 days'}

    header = [
        Paragraph('<b>P</b>', ParagraphStyle('h', fontName='Helvetica-Bold',
                   fontSize=7, textColor=COLOR_WHITE)),
        Paragraph('<b>SEV</b>', ParagraphStyle('h', fontName='Helvetica-Bold',
                   fontSize=7, textColor=COLOR_WHITE)),
        Paragraph('<b>FINDING</b>', ParagraphStyle('h', fontName='Helvetica-Bold',
                   fontSize=7, textColor=COLOR_WHITE)),
        Paragraph('<b>COMMAND</b>', ParagraphStyle('h', fontName='Helvetica-Bold',
                   fontSize=7, textColor=COLOR_WHITE)),
        Paragraph('<b>DEADLINE</b>', ParagraphStyle('h', fontName='Helvetica-Bold',
                   fontSize=7, textColor=COLOR_WHITE)),
    ]
    data = [header]

    sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2}
    sorted_rem = sorted(rem_findings, key=lambda f: sev_order.get(f.severity, 3))

    for i, f in enumerate(sorted_rem, 1):
        sc = SEV_COLORS.get(f.severity, COLOR_INFO)
        data.append([
            Paragraph(str(i), ParagraphStyle('n', fontSize=7, textColor=COLOR_TEXT_SECONDARY)),
            Paragraph(f'<b>{f.severity}</b>', ParagraphStyle('s',
                      fontName='Helvetica-Bold', fontSize=7, textColor=sc)),
            Paragraph(f.title, ParagraphStyle('t', fontSize=8, leading=11,
                      textColor=COLOR_TEXT_PRIMARY)),
            Paragraph(f'<font face="Courier" size="7">{f.remediation[:120]}</font>',
                      ParagraphStyle('c', fontSize=7, leading=10, textColor=COLOR_LOW)),
            Paragraph(deadline_map.get(f.severity, ''), ParagraphStyle('d', fontSize=7,
                      textColor=COLOR_TEXT_SECONDARY)),
        ])

    col_widths = [18, 50, 140, CONTENT_W - 278, 70]
    table = Table(data, colWidths=col_widths, repeatRows=1)
    style_cmds = [
        ('BACKGROUND', (0, 0), (-1, 0), COLOR_BG_DARK),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LINEBELOW', (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ('BOX', (0, 0), (-1, -1), 1, COLOR_BORDER),
    ]
    for i in range(1, len(data)):
        bg = COLOR_BG_PANEL if i % 2 == 1 else COLOR_BG_SUBTLE
        style_cmds.append(('BACKGROUND', (0, i), (-1, i), bg))
    table.setStyle(TableStyle(style_cmds))
    story.append(table)

    return story


# ═══════════════════════════════════════════════════
# PUBLIC API
# ═══════════════════════════════════════════════════

def generate_machine_pdf(audit: MachineAudit) -> bytes:
    """Generate a per-machine PDF report. Returns PDF bytes."""
    buffer = io.BytesIO()

    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        leftMargin=MARGIN_LEFT, rightMargin=MARGIN_RIGHT,
        topMargin=MARGIN_TOP + 10, bottomMargin=MARGIN_BOTTOM,
        title=f"Security Audit Report - {audit.hostname}",
        author="VOLDEBUG Audit Intelligence System",
        subject="Endpoint Security Audit",
        creator="VOLDEBUG v2.0",
    )
    doc._hostname = audit.hostname
    doc._report_date = audit.analyzed_at[:19] if audit.analyzed_at else ''
    doc._audit_data = audit  # for cover page callback

    story = []

    # Page 1: Cover drawn via onFirstPage callback — need a PageBreak to advance
    # Use a small invisible spacer to trigger page 1, then break to page 2
    story.append(Spacer(1, 1))
    story.append(PageBreak())

    # Page 2: Executive Summary
    story.extend(_build_executive_summary(audit))

    # Page 3: Charts
    story.extend(_build_charts_page(audit))

    # Page 4: Findings
    story.extend(_build_findings_table(audit))

    # Page 5: Remediation
    story.extend(_build_remediation_plan(audit))

    doc.build(story, onFirstPage=_draw_machine_cover, onLaterPages=_header_footer)
    buffer.seek(0)
    return buffer.read()


def generate_fleet_pdf(audits: List[MachineAudit], summary: FleetSummary) -> bytes:
    """Generate a fleet summary PDF. Returns PDF bytes."""
    buffer = io.BytesIO()

    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        leftMargin=MARGIN_LEFT, rightMargin=MARGIN_RIGHT,
        topMargin=MARGIN_TOP + 10, bottomMargin=MARGIN_BOTTOM,
        title="Fleet Security Audit Report",
        author="VOLDEBUG Audit Intelligence System",
        subject="Fleet Security Audit",
        creator="VOLDEBUG v2.0",
    )
    doc._hostname = f"Fleet ({summary.total_machines} machines)"
    doc._report_date = summary.generated_at[:19]
    doc._fleet_summary = summary  # for cover page callback

    story = []

    # Cover page via callback
    story.append(Spacer(1, 1))
    story.append(PageBreak())

    # Fleet executive summary
    story.append(Paragraph('FLEET EXECUTIVE SUMMARY', STYLE_SECTION))
    fleet_text = (
        f"Analysis of <b>{summary.total_machines} machine(s)</b> identified "
        f"<b>{summary.critical_machines}</b> at Critical risk, "
        f"<b>{summary.high_machines}</b> at High risk, "
        f"<b>{summary.medium_machines}</b> at Medium risk, and "
        f"<b>{summary.low_machines}</b> at Low risk."
    )
    story.append(Paragraph(fleet_text, STYLE_BODY))

    if summary.priority_actions:
        story.append(Spacer(1, 8))
        story.append(Paragraph('PRIORITY FLEET ACTIONS', STYLE_SECTION))
        for i, action in enumerate(summary.priority_actions, 1):
            story.append(Paragraph(f'<b>{i}.</b>  {action}', STYLE_BODY))

    # Charts: Risk bars + Heatmap
    story.append(PageBreak())
    story.append(Paragraph('FLEET RISK DASHBOARD', STYLE_SECTION))

    risk_buf = make_fleet_risk_bar(audits)
    story.append(RLImage(risk_buf, width=CONTENT_W, height=min(400, max(200, len(audits) * 25))))
    story.append(Spacer(1, 12))

    heatmap_buf = make_controls_heatmap(audits)
    story.append(RLImage(heatmap_buf, width=CONTENT_W, height=min(350, max(150, len(audits) * 22))))

    # Machine rankings table
    story.append(PageBreak())
    story.append(Paragraph('MACHINES RANKED BY RISK', STYLE_SECTION))

    header = [
        Paragraph('<b>#</b>', ParagraphStyle('h', fontName='Helvetica-Bold',
                   fontSize=7, textColor=COLOR_WHITE)),
        Paragraph('<b>HOSTNAME</b>', ParagraphStyle('h', fontName='Helvetica-Bold',
                   fontSize=7, textColor=COLOR_WHITE)),
        Paragraph('<b>SCORE</b>', ParagraphStyle('h', fontName='Helvetica-Bold',
                   fontSize=7, textColor=COLOR_WHITE)),
        Paragraph('<b>LEVEL</b>', ParagraphStyle('h', fontName='Helvetica-Bold',
                   fontSize=7, textColor=COLOR_WHITE)),
        Paragraph('<b>C</b>', ParagraphStyle('h', fontName='Helvetica-Bold',
                   fontSize=7, textColor=COLOR_CRITICAL)),
        Paragraph('<b>H</b>', ParagraphStyle('h', fontName='Helvetica-Bold',
                   fontSize=7, textColor=COLOR_HIGH)),
        Paragraph('<b>M</b>', ParagraphStyle('h', fontName='Helvetica-Bold',
                   fontSize=7, textColor=COLOR_MEDIUM)),
    ]
    data = [header]
    for i, a in enumerate(sorted(audits, key=lambda x: x.risk_score, reverse=True), 1):
        sc = severity_color(a.risk_level)
        data.append([
            str(i), a.hostname, f'{a.risk_score}/100',
            Paragraph(f'<b>{a.risk_level}</b>', ParagraphStyle('l',
                      fontName='Helvetica-Bold', fontSize=8, textColor=sc)),
            str(a.critical_count), str(a.high_count), str(a.medium_count),
        ])

    t = Table(data, colWidths=[22, 150, 55, 65, 30, 30, 30], repeatRows=1)
    style_cmds = [
        ('BACKGROUND', (0, 0), (-1, 0), COLOR_BG_DARK),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LINEBELOW', (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ('BOX', (0, 0), (-1, -1), 1, COLOR_BORDER),
    ]
    for i in range(1, len(data)):
        bg = COLOR_BG_PANEL if i % 2 == 1 else COLOR_BG_SUBTLE
        style_cmds.append(('BACKGROUND', (0, i), (-1, i), bg))
    t.setStyle(TableStyle(style_cmds))
    story.append(t)

    # Top findings
    if summary.top_findings:
        story.append(Spacer(1, 16))
        story.append(Paragraph('TOP FINDINGS ACROSS FLEET', STYLE_SECTION))
        tf_header = [
            Paragraph('<b>FINDING</b>', ParagraphStyle('h', fontName='Helvetica-Bold',
                       fontSize=7, textColor=COLOR_WHITE)),
            Paragraph('<b>MACHINES</b>', ParagraphStyle('h', fontName='Helvetica-Bold',
                       fontSize=7, textColor=COLOR_WHITE)),
            Paragraph('<b>% FLEET</b>', ParagraphStyle('h', fontName='Helvetica-Bold',
                       fontSize=7, textColor=COLOR_WHITE)),
        ]
        tf_data = [tf_header]
        for tf in summary.top_findings:
            tf_data.append([
                Paragraph(tf['title'], ParagraphStyle('t', fontSize=8, leading=11)),
                str(tf['count']),
                f"{tf['pct']}%",
            ])
        tf_table = Table(tf_data, colWidths=[CONTENT_W - 120, 60, 60], repeatRows=1)
        tf_style = [
            ('BACKGROUND', (0, 0), (-1, 0), COLOR_BG_DARK),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
            ('LINEBELOW', (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ('BOX', (0, 0), (-1, -1), 1, COLOR_BORDER),
        ]
        for i in range(1, len(tf_data)):
            bg = COLOR_BG_PANEL if i % 2 == 1 else COLOR_BG_SUBTLE
            tf_style.append(('BACKGROUND', (0, i), (-1, i), bg))
        tf_table.setStyle(TableStyle(tf_style))
        story.append(tf_table)

    doc.build(story, onFirstPage=_draw_fleet_cover, onLaterPages=_header_footer)
    buffer.seek(0)
    return buffer.read()
