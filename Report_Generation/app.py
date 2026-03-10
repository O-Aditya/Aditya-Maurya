"""
VOLDEBUG Audit Intelligence System — Streamlit Dashboard

Run: streamlit run app.py
"""
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import os
import io
import tempfile
from pathlib import Path

from voldebug.analyzer import analyze_machine, analyze_fleet, build_fleet_summary
from voldebug.loader import discover_machine_folders
from voldebug.db import init_db, save_audit_run, get_trend_data, get_all_runs
from voldebug.reports.txt_report import generate_machine_report, generate_fleet_report
from voldebug.reports.excel_report import generate_fleet_excel
from voldebug.reports.pdf_report import generate_machine_pdf, generate_fleet_pdf

# ─── Page Config ───
st.set_page_config(
    page_title="VOLDEBUG Audit Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── Custom CSS ───
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Rajdhani:wght@400;600;700&family=Share+Tech+Mono&family=Exo+2:wght@300;400;600&display=swap');

    .stApp {
        background: linear-gradient(135deg, #070b12 0%, #0d1117 50%, #111827 100%);
    }
    .main .block-container {
        max-width: 1400px;
        padding-top: 2rem;
    }
    h1, h2, h3 {
        font-family: 'Rajdhani', sans-serif !important;
        color: #00d4ff !important;
    }
    .stMetric label {
        font-family: 'Exo 2', sans-serif !important;
        color: #8892b0 !important;
    }
    .stMetric [data-testid="stMetricValue"] {
        font-family: 'Share Tech Mono', monospace !important;
    }
    div[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0a0e17 0%, #111827 100%);
        border-right: 1px solid #1e293b;
    }
    .risk-critical { color: #ff2d55; font-weight: bold; }
    .risk-high { color: #ff6b35; font-weight: bold; }
    .risk-medium { color: #ffb800; }
    .risk-low { color: #39ff14; }

    .stat-card {
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
        border: 1px solid #1e293b;
        border-radius: 12px;
        padding: 1.2rem;
        text-align: center;
        transition: border-color 0.3s;
    }
    .stat-card:hover {
        border-color: #00d4ff;
    }
    .stat-number {
        font-family: 'Share Tech Mono', monospace;
        font-size: 2.2rem;
        font-weight: 700;
    }
    .stat-label {
        font-family: 'Exo 2', sans-serif;
        color: #8892b0;
        font-size: 0.85rem;
        text-transform: uppercase;
        letter-spacing: 1px;
    }

    .finding-card {
        background: #1a1a2e;
        border-left: 4px solid;
        border-radius: 8px;
        padding: 1rem;
        margin-bottom: 0.8rem;
    }
    .finding-critical { border-left-color: #ff2d55; }
    .finding-high { border-left-color: #ff6b35; }
    .finding-medium { border-left-color: #ffb800; }
    .finding-low { border-left-color: #39ff14; }

    .posture-badge {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 0.8rem;
        font-weight: 600;
        font-family: 'Share Tech Mono', monospace;
    }
    .badge-good { background: #0d3320; color: #39ff14; border: 1px solid #39ff14; }
    .badge-bad { background: #3d0d1a; color: #ff2d55; border: 1px solid #ff2d55; }
    .badge-warn { background: #3d2d0d; color: #ffb800; border: 1px solid #ffb800; }
    .badge-unknown { background: #1a1a2e; color: #8892b0; border: 1px solid #333; }
</style>
""", unsafe_allow_html=True)


# ─── Session State ───
if "audits" not in st.session_state:
    st.session_state.audits = []
if "fleet_summary" not in st.session_state:
    st.session_state.fleet_summary = None
if "analysis_done" not in st.session_state:
    st.session_state.analysis_done = False


# ─── Sidebar ───
with st.sidebar:
    st.markdown("## 🛡️ VOLDEBUG")
    st.markdown("**Audit Intelligence System**")
    st.markdown("---")

    page = st.radio(
        "Navigation",
        ["📁 Load & Analyze", "🎯 Command Center", "🖥️ Machines",
         "🔎 Findings", "📊 Reports", "📈 Trends"],
        index=0,
    )

    st.markdown("---")
    if st.session_state.analysis_done:
        n = len(st.session_state.audits)
        avg = sum(a.risk_score for a in st.session_state.audits) / n if n else 0
        st.metric("Machines Loaded", n)
        st.metric("Avg Risk Score", f"{avg:.0f}/100")
    else:
        st.caption("No data loaded yet")

    st.markdown("---")
    st.caption("v1.0 • Enterprise Security")


# ════════════════════════════════════════════════════
# PAGE 1: Load & Analyze
# ════════════════════════════════════════════════════
if page == "📁 Load & Analyze":
    st.markdown("# 📁 Load & Analyze Audit Data")
    st.markdown("Point to a folder containing VOLDEBUG machine audit data.")

    col1, col2 = st.columns([3, 1])
    with col1:
        folder_path = st.text_input(
            "Audit Data Path",
            value=str(Path(__file__).parent),
            help="Enter the path to a folder containing VOLDEBUG_* audit folders, or a single machine folder.",
        )
    with col2:
        st.markdown("<br>", unsafe_allow_html=True)
        analyze_btn = st.button("⚡ Analyze", type="primary", use_container_width=True)

    if analyze_btn and folder_path:
        with st.spinner("Discovering machine folders..."):
            machines = discover_machine_folders(folder_path)

        if not machines:
            st.error(f"No VOLDEBUG machine folders found in: {folder_path}")
        else:
            st.info(f"Found **{len(machines)}** machine folder(s)")

            progress = st.progress(0, text="Analyzing machines...")
            audits = []
            for i, machine_path in enumerate(machines):
                progress.progress(
                    (i + 1) / len(machines),
                    text=f"Analyzing {machine_path.name}... ({i+1}/{len(machines)})"
                )
                try:
                    audit = analyze_machine(str(machine_path))
                    audits.append(audit)
                except Exception as e:
                    st.warning(f"Failed to analyze {machine_path.name}: {e}")

            if audits:
                st.session_state.audits = audits
                st.session_state.fleet_summary = build_fleet_summary(audits)
                st.session_state.analysis_done = True

                # Save to database
                try:
                    run_id = save_audit_run(audits, notes=f"Analyzed from {folder_path}")
                    st.success(f"✅ Analysis complete! {len(audits)} machine(s) analyzed. Saved to database (Run #{run_id}).")
                except Exception as e:
                    st.success(f"✅ Analysis complete! {len(audits)} machine(s) analyzed.")
                    st.warning(f"Could not save to database: {e}")

                st.rerun()

    # Show current state
    if st.session_state.analysis_done:
        st.markdown("### Current Analysis")
        audits = st.session_state.audits
        cols = st.columns(5)
        with cols[0]:
            st.metric("Machines", len(audits))
        with cols[1]:
            crit = sum(a.critical_count for a in audits)
            st.metric("CRITICAL", crit, delta=None)
        with cols[2]:
            high = sum(a.high_count for a in audits)
            st.metric("HIGH", high)
        with cols[3]:
            total = sum(len(a.findings) for a in audits)
            st.metric("Total Findings", total)
        with cols[4]:
            avg = sum(a.risk_score for a in audits) / len(audits) if audits else 0
            st.metric("Avg Risk", f"{avg:.0f}")


# ════════════════════════════════════════════════════
# PAGE 2: Command Center
# ════════════════════════════════════════════════════
elif page == "🎯 Command Center":
    st.markdown("# 🎯 Command Center")

    if not st.session_state.analysis_done:
        st.warning("No data loaded. Go to **📁 Load & Analyze** first.")
        st.stop()

    audits = st.session_state.audits
    fleet = st.session_state.fleet_summary

    # ── Stat Cards ──
    col1, col2, col3, col4, col5 = st.columns(5)
    metrics = [
        ("🖥️ Machines", len(audits)),
        ("🔴 CRITICAL", fleet.critical_machines),
        ("🟠 HIGH", fleet.high_machines),
        ("🟡 MEDIUM", fleet.medium_machines),
        ("🟢 LOW", fleet.low_machines),
    ]
    for col, (label, val) in zip([col1, col2, col3, col4, col5], metrics):
        with col:
            st.markdown(f"""
            <div class="stat-card">
                <div class="stat-number">{val}</div>
                <div class="stat-label">{label}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Charts Row ──
    ch1, ch2 = st.columns(2)

    with ch1:
        # Risk Distribution Donut
        risk_data = pd.DataFrame({
            "Level": ["Critical", "High", "Medium", "Low"],
            "Count": [fleet.critical_machines, fleet.high_machines,
                      fleet.medium_machines, fleet.low_machines],
        })
        fig = px.pie(
            risk_data, values="Count", names="Level",
            color="Level",
            color_discrete_map={"Critical": "#ff2d55", "High": "#ff6b35",
                                "Medium": "#ffb800", "Low": "#39ff14"},
            hole=0.55,
        )
        fig.update_layout(
            title="Risk Distribution",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#ccd6f6", family="Exo 2"),
            showlegend=True,
            height=350,
        )
        st.plotly_chart(fig, use_container_width=True)

    with ch2:
        # Fleet Risk Bar Chart
        bar_data = pd.DataFrame({
            "Machine": [a.hostname for a in sorted(audits, key=lambda x: x.risk_score, reverse=True)],
            "Score": [a.risk_score for a in sorted(audits, key=lambda x: x.risk_score, reverse=True)],
            "Level": [a.risk_level for a in sorted(audits, key=lambda x: x.risk_score, reverse=True)],
        })
        fig2 = px.bar(
            bar_data, x="Score", y="Machine", orientation="h",
            color="Level",
            color_discrete_map={"Critical": "#ff2d55", "High": "#ff6b35",
                                "Medium": "#ffb800", "Low": "#39ff14"},
        )
        fig2.update_layout(
            title="Machines by Risk Score",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#ccd6f6", family="Exo 2"),
            xaxis=dict(gridcolor="#1e293b", range=[0, 100]),
            yaxis=dict(gridcolor="#1e293b"),
            height=350,
        )
        st.plotly_chart(fig2, use_container_width=True)

    # ── Top Findings ──
    st.markdown("### 🔥 Top Findings Across Fleet")
    if fleet.top_findings:
        tf_data = pd.DataFrame(fleet.top_findings)
        tf_data.columns = ["Finding", "Machines Affected", "% of Fleet"]
        st.dataframe(tf_data, use_container_width=True, hide_index=True)

    # ── Priority Actions ──
    if fleet.priority_actions:
        st.markdown("### ⚡ Priority Fleet Actions")
        for i, action in enumerate(fleet.priority_actions, 1):
            st.markdown(f"**{i}.** {action}")


# ════════════════════════════════════════════════════
# PAGE 3: Machines
# ════════════════════════════════════════════════════
elif page == "🖥️ Machines":
    st.markdown("# 🖥️ Machine Details")

    if not st.session_state.analysis_done:
        st.warning("No data loaded. Go to **📁 Load & Analyze** first.")
        st.stop()

    audits = st.session_state.audits

    # Sort options
    sort_opt = st.selectbox("Sort by", ["Risk Score (High→Low)", "Risk Score (Low→High)", "Hostname"])
    if "High→Low" in sort_opt:
        audits_sorted = sorted(audits, key=lambda a: a.risk_score, reverse=True)
    elif "Low→High" in sort_opt:
        audits_sorted = sorted(audits, key=lambda a: a.risk_score)
    else:
        audits_sorted = sorted(audits, key=lambda a: a.hostname)

    for audit in audits_sorted:
        sp = audit.security_posture
        sinfo = audit.system_info

        # Risk badge
        risk_class = audit.risk_level.lower()
        color_map = {"critical": "#ff2d55", "high": "#ff6b35", "medium": "#ffb800", "low": "#39ff14"}
        risk_color = color_map.get(risk_class, "#888")

        with st.expander(
            f"{'🔴' if risk_class == 'critical' else '🟠' if risk_class == 'high' else '🟡' if risk_class == 'medium' else '🟢'} "
            f"**{audit.hostname}** — Score: {audit.risk_score}/100 ({audit.risk_level}) — "
            f"C:{audit.critical_count} H:{audit.high_count} M:{audit.medium_count}"
        ):
            # System Overview
            c1, c2, c3 = st.columns(3)
            with c1:
                st.markdown("#### System Info")
                st.text(f"Hostname:  {sinfo.hostname}")
                st.text(f"IP:        {sinfo.ip}")
                st.text(f"OS:        {sinfo.os_name}")
                st.text(f"Model:     {sinfo.manufacturer} {sinfo.model}")
                st.text(f"Serial:    {sinfo.serial}")
                st.text(f"Domain:    {sinfo.domain or 'WORKGROUP'}")

            with c2:
                st.markdown("#### Security Posture")

                def badge(label, val_true, val_false=None, val=None):
                    if val is True:
                        return f'<span class="posture-badge badge-good">{label}: ✓</span>'
                    elif val is False:
                        return f'<span class="posture-badge badge-bad">{label}: ✗</span>'
                    return f'<span class="posture-badge badge-unknown">{label}: ?</span>'

                badges = [
                    badge("BitLocker", True, False, sp.bitlocker_enabled),
                    badge("Defender", True, False, sp.defender_running),
                    badge("EDR", True, False, sp.edr_detected),
                    badge("FW Domain", True, False, sp.firewall_domain),
                    badge("FW Private", True, False, sp.firewall_private),
                    badge("FW Public", True, False, sp.firewall_public),
                ]
                st.markdown(" ".join(badges), unsafe_allow_html=True)
                if sp.edr_detected:
                    st.text(f"EDR: {sp.edr_name}")
                st.text(f"Patch Gap: {audit.patch_gap_days}d" if audit.patch_gap_days >= 0 else "Patch Gap: Unknown")
                st.text(f"Local Admins: {len(audit.local_admins)}")

            with c3:
                st.markdown("#### Event Summary")
                es = audit.event_summary
                st.text(f"Failed Logons:     {es.failed_logons}")
                st.text(f"Explicit Creds:    {es.explicit_cred_use}")
                st.text(f"New Services:      {es.new_service}")
                st.text(f"Logs Cleared:      {es.log_cleared}")
                st.text(f"Unclean Shutdowns: {es.unclean_shutdown}")
                st.text(f"Tasks Created:     {es.task_created}")

            # Findings
            st.markdown("#### Findings")
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                sev_findings = [f for f in audit.findings if f.severity == sev]
                if not sev_findings:
                    continue
                sev_class = sev.lower()
                for f in sev_findings:
                    compound_tag = "🔗 COMPOUND — " if f.is_compound else ""
                    st.markdown(f"""
                    <div class="finding-card finding-{sev_class}">
                        <strong>[{f.severity}]</strong> {compound_tag}{f.title}<br>
                        <small style="color:#8892b0">{f.category} | Owner: {f.owner}</small><br>
                        <span style="color:#ccd6f6">{f.description[:300]}</span>
                        {'<br><code style="color:#39ff14">FIX: ' + f.remediation[:150] + '</code>' if f.remediation else ''}
                        {'<br><em style="color:#ff6b35">🎯 ' + f.attacker_context[:150] + '</em>' if f.attacker_context else ''}
                    </div>
                    """, unsafe_allow_html=True)

            # Persistence
            pers = audit.persistence
            if pers.registry_run_keys or pers.suspicious_tasks or pers.non_standard_services:
                st.markdown("#### Persistence Analysis")
                pc1, pc2, pc3, pc4 = st.columns(4)
                pc1.metric("Run Keys", len(pers.registry_run_keys))
                pc2.metric("Tasks", len(pers.suspicious_tasks))
                pc3.metric("Services", len(pers.non_standard_services))
                pc4.metric("Startup", len(pers.startup_items))


# ════════════════════════════════════════════════════
# PAGE 4: Findings
# ════════════════════════════════════════════════════
elif page == "🔎 Findings":
    st.markdown("# 🔎 All Findings")

    if not st.session_state.analysis_done:
        st.warning("No data loaded. Go to **📁 Load & Analyze** first.")
        st.stop()

    audits = st.session_state.audits

    # Build findings dataframe
    all_findings = []
    for audit in audits:
        for f in audit.findings:
            all_findings.append({
                "Severity": f.severity,
                "Category": f.category,
                "Machine": audit.hostname,
                "Title": f.title,
                "Description": f.description[:200],
                "Remediation": f.remediation[:150],
                "Owner": f.owner,
                "Compound": "🔗" if f.is_compound else "",
            })

    df = pd.DataFrame(all_findings)

    if df.empty:
        st.success("No findings detected!")
        st.stop()

    # Filters
    fc1, fc2, fc3, fc4 = st.columns(4)
    with fc1:
        sev_filter = st.multiselect("Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                                     default=["CRITICAL", "HIGH", "MEDIUM"])
    with fc2:
        categories = sorted(df["Category"].unique())
        cat_filter = st.multiselect("Category", categories, default=categories)
    with fc3:
        machines = sorted(df["Machine"].unique())
        mach_filter = st.multiselect("Machine", machines, default=machines)
    with fc4:
        search = st.text_input("🔍 Search", "")

    # Apply filters
    mask = (df["Severity"].isin(sev_filter) &
            df["Category"].isin(cat_filter) &
            df["Machine"].isin(mach_filter))

    if search:
        search_mask = df.apply(lambda r: search.lower() in r.to_string().lower(), axis=1)
        mask = mask & search_mask

    filtered = df[mask]

    # Sort by severity
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    filtered = filtered.copy()
    filtered["_order"] = filtered["Severity"].map(sev_order)
    filtered = filtered.sort_values("_order").drop("_order", axis=1)

    st.markdown(f"**{len(filtered)}** findings shown (of {len(df)} total)")
    st.dataframe(filtered, use_container_width=True, hide_index=True, height=600)


# ════════════════════════════════════════════════════
# PAGE 5: Reports
# ════════════════════════════════════════════════════
elif page == "📊 Reports":
    st.markdown("# 📊 Reports")

    if not st.session_state.analysis_done:
        st.warning("No data loaded. Go to **📁 Load & Analyze** first.")
        st.stop()

    audits = st.session_state.audits
    fleet = st.session_state.fleet_summary

    # ── Batch ZIP download ──
    st.markdown("### ⚡ Batch Download")
    if st.button("� Generate All PDFs (ZIP)", type="primary", use_container_width=True, key="gen_zip"):
        import zipfile
        zip_buffer = io.BytesIO()
        progress = st.progress(0, text="Generating PDFs...")
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            for i, audit in enumerate(sorted(audits, key=lambda a: a.risk_score, reverse=True)):
                progress.progress(
                    (i + 1) / (len(audits) + 1),
                    text=f"Generating: {audit.hostname} ({i+1}/{len(audits)})"
                )
                try:
                    pdf_bytes = generate_machine_pdf(audit)
                    zf.writestr(f"VOLDEBUG_Report_{audit.hostname}.pdf", pdf_bytes)
                except Exception:
                    pass
            # Add fleet PDF
            progress.progress(1.0, text="Generating fleet summary...")
            try:
                fleet_pdf = generate_fleet_pdf(audits, fleet)
                zf.writestr("VOLDEBUG_Fleet_Summary.pdf", fleet_pdf)
            except Exception:
                pass
        zip_buffer.seek(0)
        st.download_button(
            "📦 Download All Reports (ZIP)",
            data=zip_buffer.read(),
            file_name="VOLDEBUG_All_Reports.zip",
            mime="application/zip",
            use_container_width=True,
            key="dl_zip_all",
        )

    st.markdown("---")

    # ── Per-machine PDF downloads ──
    st.markdown("### 📄 Per-Machine PDF Reports")
    for i, audit in enumerate(sorted(audits, key=lambda a: a.risk_score, reverse=True)):
        risk_icon = '🔴' if audit.risk_level == 'Critical' else '🟠' if audit.risk_level == 'High' else '🟡' if audit.risk_level == 'Medium' else '🟢'
        try:
            with st.spinner(f"Generating PDF for {audit.hostname}..."):
                pdf_data = generate_machine_pdf(audit)
            st.download_button(
                f"{risk_icon} {audit.hostname} — {audit.risk_level} ({audit.risk_score}/100)  📄 PDF",
                data=pdf_data,
                file_name=f"VOLDEBUG_Report_{audit.hostname}.pdf",
                mime="application/pdf",
                use_container_width=True,
                key=f"dl_pdf_{i}_{audit.hostname}",
            )
        except Exception as e:
            st.error(f"PDF generation failed for {audit.hostname}: {e}")

    st.markdown("---")

    # ── Fleet reports ──
    st.markdown("### 📊 Fleet Reports")
    col1, col2, col3 = st.columns(3)
    with col1:
        try:
            with st.spinner("Generating fleet PDF..."):
                fleet_pdf_data = generate_fleet_pdf(audits, fleet)
            st.download_button(
                "📄 Fleet Summary (PDF)",
                data=fleet_pdf_data,
                file_name="VOLDEBUG_Fleet_Summary.pdf",
                mime="application/pdf",
                use_container_width=True,
                key="dl_fleet_pdf",
            )
        except Exception as e:
            st.error(f"Fleet PDF failed: {e}")

    with col2:
        try:
            tmp_path = os.path.join(tempfile.gettempdir(), "voldebug_fleet_report.xlsx")
            generate_fleet_excel(audits, fleet, tmp_path)
            with open(tmp_path, "rb") as f:
                excel_data = f.read()
            st.download_button(
                "📊 Fleet Report (Excel)",
                data=excel_data,
                file_name="VOLDEBUG_Fleet_Report.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                use_container_width=True,
                key="dl_fleet_excel",
            )
        except Exception as e:
            st.error(f"Excel generation failed: {e}")

    with col3:
        fleet_txt = generate_fleet_report(fleet)
        st.download_button(
            "📝 Fleet Summary (TXT)",
            data=fleet_txt,
            file_name="VOLDEBUG_Fleet_Summary.txt",
            mime="text/plain",
            use_container_width=True,
            key="dl_fleet_txt",
        )

    # Report preview
    st.markdown("---")
    st.markdown("### 🔍 Report Preview")
    preview_machine = st.selectbox(
        "Select machine to preview",
        [a.hostname for a in sorted(audits, key=lambda a: a.risk_score, reverse=True)]
    )
    if preview_machine:
        audit = next(a for a in audits if a.hostname == preview_machine)
        report = generate_machine_report(audit)
        st.code(report, language="text")



# ════════════════════════════════════════════════════
# PAGE 6: Trends
# ════════════════════════════════════════════════════
elif page == "📈 Trends":
    st.markdown("# 📈 Historical Trends")

    try:
        init_db()
        runs = get_all_runs()
    except Exception:
        runs = []

    if not runs:
        st.info("No historical data yet. Run an analysis to start tracking trends.")
        if st.session_state.analysis_done:
            st.markdown("Current analysis is saved. Run another analysis later to see trends.")
    else:
        st.markdown(f"### {len(runs)} Audit Run(s) on Record")

        runs_df = pd.DataFrame(runs)
        runs_df = runs_df[["id", "run_date", "total_machines", "avg_risk_score",
                            "critical_count", "high_count", "medium_count", "low_count"]]
        runs_df.columns = ["Run #", "Date", "Machines", "Avg Risk",
                            "Critical", "High", "Medium", "Low"]
        st.dataframe(runs_df, use_container_width=True, hide_index=True)

        # Trend chart
        if len(runs) >= 2:
            st.markdown("### Risk Score Trend")
            trend_df = pd.DataFrame(runs)
            fig = px.line(
                trend_df, x="run_date", y="avg_risk_score",
                markers=True,
                title="Average Fleet Risk Score Over Time",
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#ccd6f6", family="Exo 2"),
                xaxis=dict(gridcolor="#1e293b"),
                yaxis=dict(gridcolor="#1e293b", range=[0, 100]),
            )
            fig.update_traces(line_color="#00d4ff")
            st.plotly_chart(fig, use_container_width=True)
