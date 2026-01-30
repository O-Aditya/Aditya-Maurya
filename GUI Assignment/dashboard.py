import streamlit as st
import requests
import pandas as pd
import altair as alt
import subprocess
import sys
import time
import requests
import os  # <--- Add this import


# --- AUTO-START API SERVER (ROBUST VERSION) ---
def start_api_server():
    """Starts the FastAPI backend in a background process."""
    # Check if API is already running
    try:
        requests.get("http://127.0.0.1:8000")
        print("✅ API is already running.")
    except requests.exceptions.ConnectionError:
        print("🚀 Starting API Server...")
        
        # Get the folder where this script (dashboard.py) is located
        script_dir = os.path.dirname(os.path.abspath(__file__))

        # Start server.py in the background, specifically IN that folder
        subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "server:app", "--host", "127.0.0.1", "--port", "8000"],
            cwd=script_dir,  # <--- CRITICAL FIX: Run command inside the folder
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(3)  # Wait for it to boot

start_api_server()

# --- CONFIGURATION ---
API_URL = "http://127.0.0.1:8000"
PAGE_TITLE = "Forensic Dashboard"
PAGE_ICON = "🛡️"

st.set_page_config(page_title=PAGE_TITLE, page_icon=PAGE_ICON, layout="wide")

# --- CSS FOR MODERN UI ---
st.markdown("""
<style>
    .block-container { padding-top: 2rem; padding-bottom: 2rem; }
    [data-testid="stMetricValue"] { font-size: 26px; font-weight: 700; }
    div[data-testid="stVerticalBlockBorderWrapper"] { border-radius: 8px; border: 1px solid #f0f2f6; }
    
    /* Alert Box Styling */
    .alert-box {
        padding: 1rem;
        border-radius: 8px;
        background-color: #ff4b4b20;
        border: 1px solid #ff4b4b;
        color: #ff4b4b;
        margin-bottom: 1rem;
    }
</style>
""", unsafe_allow_html=True)

# --- HELPER FUNCTIONS ---
def fetch_data(endpoint):
    try:
        response = requests.get(f"{API_URL}/{endpoint}")
        if response.status_code == 200:
            return response.json()
    except:
        return None
    return None

# --- MODAL DIALOG ---
@st.dialog("📄 Report Viewer", width="large")
def show_report_modal(filename, forensic_value, sensitivity):
    with st.spinner("Retrieving secure document..."):
        content_data = fetch_data(f"reports/{filename}")
    
    if content_data:
        content = content_data.get("content", "No content available.")
        c1, c2 = st.columns(2)
        c1.info(f"**Risk Level:** {sensitivity}")
        c2.success(f"**Forensic Value:** {forensic_value}")
        
        st.download_button("⬇️ Download Report (.md)", data=content, file_name=filename, mime="text/markdown", use_container_width=True)
        st.divider()
        st.markdown(content)
    else:
        st.error("Could not load report content.")

# --- SIDEBAR ---
with st.sidebar:
    st.header(f"{PAGE_ICON} Menu")
    if st.button("Refresh Data", icon="🔄", use_container_width=True):
        st.rerun()
    
    st.markdown("---")
    
    # NEW: Export Feature
    st.markdown("**Data Export**")
    reports_raw = fetch_data("reports")
    if reports_raw:
        df_export = pd.DataFrame(reports_raw)
        csv = df_export.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📥 Download Summary CSV",
            data=csv,
            file_name="forensic_audit_summary.csv",
            mime="text/csv",
            use_container_width=True
        )

    st.markdown("---")
    stats = fetch_data("stats")
    if stats:
        st.caption("🟢 API Online")
        st.caption(f"Indexed: {stats.get('total_files', 0)} files")
    else:
        st.error("🔴 API Offline")
        st.stop()

# --- MAIN LAYOUT ---
st.title("Cybersecurity Audit Center")
st.markdown("#### Real-time Forensic Analysis & Threat Detection")
st.markdown("---")

# 1. KEY METRICS
col1, col2, col3, col4 = st.columns(4)
col1.metric("Files Scanned", stats.get("total_files", 0))
col2.metric("Critical Threats", stats.get("high_sensitivity", 0))
col3.metric("Medium Risks", stats.get("medium_sensitivity", 0))
col4.metric("Clean Artifacts", stats.get("low_sensitivity", 0))

# 2. PRIORITY ALERTS (NEW FEATURE)
reports_data = fetch_data("reports")
df = pd.DataFrame(reports_data) if reports_data else pd.DataFrame()

if not df.empty:
    # Filter for High/Critical Risks
    critical_df = df[df['sensitivity'].str.contains("High|Critical", case=False, na=False)]
    
    if not critical_df.empty:
        st.error(f"⚠️ **ACTION REQUIRED: {len(critical_df)} Critical Artifacts Detected**")
        with st.expander("View High-Priority Threats", expanded=True):
            for _, row in critical_df.iterrows():
                c1, c2 = st.columns([4, 1])
                c1.markdown(f"**🔴 {row['title']}**")
                if c2.button("View", key=f"alert_{row['filename']}"):
                    show_report_modal(row['filename'], row.get('forensic_value', 'Unknown'), row.get('sensitivity', 'Unknown'))
    else:
        st.success("✅ System Status: No Critical Threats Detected.")

st.markdown("---")

# 3. ADVANCED VISUALIZATION (UPDATED)
if not df.empty:
    st.subheader("📊 Analytics Dashboard")
    
    chart_col1, chart_col2 = st.columns(2)
    
    with chart_col1:
        st.markdown("**Threat Distribution**")
        source = pd.DataFrame({
            'Risk Level': ['High', 'Medium', 'Low'],
            'Count': [stats.get('high_sensitivity', 0), stats.get('medium_sensitivity', 0), stats.get('low_sensitivity', 0)]
        })
        chart = alt.Chart(source).mark_bar(cornerRadius=5).encode(
            x=alt.X('Risk Level', sort=['High', 'Medium', 'Low']),
            y='Count',
            color=alt.Color('Risk Level', scale=alt.Scale(domain=['High', 'Medium', 'Low'], range=['#FF4B4B', '#FFA500', '#00CC96'])),
            tooltip=['Risk Level', 'Count']
        ).properties(height=250)
        st.altair_chart(chart, use_container_width=True)

    with chart_col2:
        # NEW CHART: Forensic Value Breakdown
        st.markdown("**Forensic Evidence Value**")
        if 'forensic_value' in df.columns:
            value_counts = df['forensic_value'].value_counts().reset_index()
            value_counts.columns = ['Value', 'Count']
            
            donut = alt.Chart(value_counts).mark_arc(innerRadius=50).encode(
                theta=alt.Theta("Count"),
                color=alt.Color("Value", scale=alt.Scale(scheme='magma')),
                tooltip=["Value", "Count"]
            ).properties(height=250)
            st.altair_chart(donut, use_container_width=True)

    st.markdown("---")

    # 4. REPORT GRID WITH SEARCH
    st.subheader("📂 Forensic Reports")
    search = st.text_input("🔍 Search Logs...", placeholder="Type filename, risk level, or keyword...")
    
    if search:
        df = df[df['title'].str.contains(search, case=False) | df['filename'].str.contains(search, case=False) | df['sensitivity'].str.contains(search, case=False)]

    if not df.empty:
        grid_cols = st.columns(2)
        for index, row in df.iterrows():
            with grid_cols[index % 2]:
                with st.container(border=True):
                    c1, c2 = st.columns([3, 1])
                    
                    icon = "🟢"
                    if "High" in row.get('sensitivity', '') or "Critical" in row.get('sensitivity', ''): icon = "🔴"
                    elif "Medium" in row.get('sensitivity', ''): icon = "🟠"

                    c1.markdown(f"**{icon} {row['title']}**")
                    c2.caption(f"**{row.get('sensitivity', 'Unknown')}**")
                    st.caption(row.get('summary_preview', 'No summary.')[:100] + "...")
                    
                    if st.button("View Analysis", key=f"btn_{row['filename']}", use_container_width=True):
                        show_report_modal(row['filename'], row.get('forensic_value', 'Unknown'), row.get('sensitivity', 'Unknown'))
    else:
        st.info("No reports matched your search.")
else:
    st.info("No reports found. Please check your data source.")