import streamlit as st
import requests
import pandas as pd
import altair as alt

# --- CONFIGURATION ---
API_URL = "http://127.0.0.1:8000"
PAGE_TITLE = "Forensic Dashboard"
PAGE_ICON = "🛡️"

st.set_page_config(page_title=PAGE_TITLE, page_icon=PAGE_ICON, layout="wide")

# --- CSS FOR MODERN UI ---
st.markdown("""
<style>
    /* Clean up spacing */
    .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
    }
    /* Metric cards styling */
    [data-testid="stMetricValue"] {
        font-size: 26px;
        font-weight: 700;
    }
    /* Minimalist card border */
    div[data-testid="stVerticalBlockBorderWrapper"] {
        border-radius: 8px;
        border: 1px solid #f0f2f6;
    }
</style>
""", unsafe_allow_html=True)

# --- HELPER FUNCTIONS ---
def fetch_data(endpoint):
    """Generic fetcher for API data."""
    try:
        response = requests.get(f"{API_URL}/{endpoint}")
        if response.status_code == 200:
            return response.json()
    except:
        return None
    return None

# --- MODAL DIALOG (The "Top Up Window") ---
@st.dialog("📄 Report Viewer", width="large")
def show_report_modal(filename, forensic_value, sensitivity):
    """Opens the report in a focused pop-up window with Download."""
    
    # Fetch content inside the modal
    with st.spinner("Retrieving secure document..."):
        content_data = fetch_data(f"reports/{filename}")
    
    if content_data:
        content = content_data.get("content", "No content available.")
        
        # Metadata Header
        c1, c2 = st.columns(2)
        c1.info(f"**Risk Level:** {sensitivity}")
        c2.success(f"**Forensic Value:** {forensic_value}")
        
        # Download Button (Restored & Functional)
        st.download_button(
            label="⬇️ Download Report (.md)",
            data=content,
            file_name=filename,
            mime="text/markdown",
            use_container_width=True
        )
        
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

# 2. VISUALIZATION (RESTORED CHART)
# We fetch reports first to generate the chart data
reports_data = fetch_data("reports")

if reports_data:
    st.subheader("📊 Threat Landscape")
    
    # Create Data for Chart
    source = pd.DataFrame({
        'Risk Level': ['High', 'Medium', 'Low'],
        'Count': [
            stats.get('high_sensitivity', 0), 
            stats.get('medium_sensitivity', 0), 
            stats.get('low_sensitivity', 0)
        ]
    })
    
    # The Altair Chart
    chart = alt.Chart(source).mark_bar(cornerRadiusTopLeft=3, cornerRadiusTopRight=3).encode(
        x=alt.X('Risk Level', sort=['High', 'Medium', 'Low']),
        y='Count',
        color=alt.Color('Risk Level', scale=alt.Scale(domain=['High', 'Medium', 'Low'], range=['#FF4B4B', '#FFA500', '#00CC96'])),
        tooltip=['Risk Level', 'Count']
    ).properties(height=200)
    
    st.altair_chart(chart, use_container_width=True)

    st.markdown("---")

    # 3. REPORT GRID WITH SEARCH
    st.subheader("📂 Forensic Reports")
    
    # Search Bar
    df = pd.DataFrame(reports_data)
    search = st.text_input("🔍 Search Logs...", placeholder="Type filename, risk level (e.g. 'High'), or keyword...")
    
    if search:
        df = df[df['title'].str.contains(search, case=False) | df['filename'].str.contains(search, case=False) | df['sensitivity'].str.contains(search, case=False)]

    if not df.empty:
        # Create a 2-column grid
        grid_cols = st.columns(2)
        
        for index, row in df.iterrows():
            # Toggle columns
            with grid_cols[index % 2]:
                with st.container(border=True):
                    # Header Row
                    c1, c2 = st.columns([3, 1])
                    
                    # Risk Icon
                    icon = "🟢"
                    if "High" in row.get('sensitivity', '') or "Critical" in row.get('sensitivity', ''):
                        icon = "🔴"
                    elif "Medium" in row.get('sensitivity', ''):
                        icon = "🟠"

                    c1.markdown(f"**{icon} {row['title']}**")
                    c2.caption(f"**{row.get('sensitivity', 'Unknown')}**")
                    
                    # Summary Preview
                    st.caption(row.get('summary_preview', 'No summary available.')[:100] + "...")
                    
                    # View Button (Opens Modal)
                    if st.button("View Analysis", key=f"btn_{row['filename']}", use_container_width=True):
                        show_report_modal(
                            row['filename'], 
                            row.get('forensic_value', 'Unknown'), 
                            row.get('sensitivity', 'Unknown')
                        )
    else:
        st.info("No reports matched your search.")

else:
    st.info("No reports found. Please check your data source.")