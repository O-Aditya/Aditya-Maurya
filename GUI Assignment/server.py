import os
import re
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional

# --- CONFIGURATION ---
app = FastAPI(
    title="Forensic Analysis API",
    description="API for serving automated security audit reports.",
    version="2.0"
)

# Enable CORS (so your GUI can talk to this API)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Directory where your .md reports are saved
REPORT_DIR = "Report"  

# --- DATA MODELS ---
class ReportSummary(BaseModel):
    filename: str
    title: str
    sensitivity: str  # e.g., "High", "Medium"
    forensic_value: str
    summary_preview: str

class ReportDetail(BaseModel):
    filename: str
    content: str

class DashboardStats(BaseModel):
    total_files: int
    high_sensitivity: int
    medium_sensitivity: int
    low_sensitivity: int

# --- HELPER: MARKDOWN PARSER ---
def parse_report_metadata(content: str, filename: str):
    """
    Reads the raw Markdown and extracts structured fields 
    using the specific format we defined in the reports.
    """
    metadata = {
        "filename": filename,
        "title": filename.replace("Audit_Report_", "").replace(".md", "").replace("_", " ").title(),
        "sensitivity": "Unknown",
        "forensic_value": "Unknown",
        "summary_preview": "No summary available."
    }

    # 1. Extract Sensitivity Level
    # Pattern: **Data Sensitivity Level:** High
    sens_match = re.search(r"\*\*Data Sensitivity Level:\*\*\s*(.+)", content)
    if sens_match:
        metadata["sensitivity"] = sens_match.group(1).strip()

    # 2. Extract Forensic Value
    # Pattern: **Forensic Value:** Critical
    val_match = re.search(r"\*\*Forensic Value:\*\*\s*(.+)", content)
    if val_match:
        metadata["forensic_value"] = val_match.group(1).strip()

    # 3. Extract Executive Summary (First 200 chars)
    # Pattern: Look for text after "## 6. Executive Summary"
    sum_match = re.search(
        r"## 6\. Executive Summary\s*(.*?)(?=\n## |\Z)",
        content,
        re.DOTALL
    )

    if sum_match:
        clean_summary = sum_match.group(1)

        # remove markdown bold
        clean_summary = re.sub(r"\*\*", "", clean_summary)

        # collapse lines
        clean_summary = " | ".join(
            line.strip()
            for line in clean_summary.splitlines()
            if line.strip()
        )

        metadata["summary_preview"] = (
            clean_summary[:200] + "..."
            if len(clean_summary) > 200
            else clean_summary
        )
    return metadata

# --- API ENDPOINTS ---

@app.get("/")
def health_check():
    """Confirms the API is running."""
    return {"status": "online", "system": "Forensic API v2"}

@app.get("/reports", response_model=List[ReportSummary])
def list_reports():
    """Lists all analyzed files with their calculated risk levels."""
    if not os.path.exists(REPORT_DIR):
        return []

    results = []
    for f in os.listdir(REPORT_DIR):
        if f.endswith(".md"):
            filepath = os.path.join(REPORT_DIR, f)
            try:
                with open(filepath, "r", encoding="utf-8") as file:
                    content = file.read()
                    meta = parse_report_metadata(content, f)
                    results.append(meta)
            except Exception as e:
                print(f"Error parsing {f}: {e}")
                
    return results

@app.get("/reports/{filename}", response_model=ReportDetail)
def get_report_content(filename: str):
    """Returns the full raw Markdown content for a specific file."""
    filepath = os.path.join(REPORT_DIR, filename)
    
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="Report not found")
    
    with open(filepath, "r", encoding="utf-8") as f:
        return {
            "filename": filename,
            "content": f.read()
        }

@app.get("/stats", response_model=DashboardStats)
def get_dashboard_stats():
    """Returns aggregated metrics for the dashboard charts."""
    reports = list_reports()
    
    total = len(reports)
    high = sum(1 for r in reports if "High" in r.get("sensitivity", "") or "Critical" in r.get("sensitivity", ""))
    medium = sum(1 for r in reports if "Medium" in r.get("sensitivity", ""))
    low = sum(1 for r in reports if "Low" in r.get("sensitivity", ""))

    return {
        "total_files": total,
        "high_sensitivity": high,
        "medium_sensitivity": medium,
        "low_sensitivity": low
    }