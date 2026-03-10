# Report Generation — VOLDEBUG Audit Intelligence System

A full-stack **security audit intelligence dashboard** built with **Streamlit** for analyzing Windows endpoint audit data collected by the VOLDEBUG collector tool. The system parses raw telemetry from machines, scores risk, surfaces hidden threats, and generates professional PDF/Excel/TXT reports.

## 🚀 Features

| Feature | Description |
| :--- | :--- |
| **Fleet-Wide Analysis** | Load and analyze audit data from 1 to 10,000+ Windows machines in a single run |
| **Risk Scoring Engine** | Weighted 0–100 risk scoring with severity tiers (Critical / High / Medium / Low) and compound-risk detection |
| **Interactive Dashboard** | Command Center with Plotly donut charts, bar graphs, filterable findings table, and machine deep-dives |
| **Multi-Format Reports** | Export per-machine **PDF**, fleet summary **PDF**, **Excel**, and **TXT** reports — plus a batch ZIP download |
| **Historical Trends** | SQLite-backed audit run storage with time-series risk trend charts |
| **Persistence & Forensics** | Detects registry run keys, suspicious scheduled tasks, non-standard services, and startup items |
| **Event Log Intelligence** | Correlates Windows Security, System, Application, Defender, and PowerShell event channels |

## 📂 Project Structure

```
Report_Generation/
├── app.py                        # Streamlit dashboard (main entry point)
├── requirements.txt              # Python dependencies
├── VOLDEBUG_System_Prompt.md     # AI system prompt / analysis methodology docs
├── voldebug_audit.db             # SQLite database (auto-generated on first run)
├── VOLDEBUG_All_Reports.zip      # Sample batch export of all PDF reports
│
└── voldebug/                     # Core Python package
    ├── __init__.py
    ├── analyzer.py               # Machine & fleet analysis logic
    ├── loader.py                 # Discovers and loads VOLDEBUG machine folders
    ├── models.py                 # Data models (Audit, Finding, SecurityPosture, etc.)
    ├── scorer.py                 # Risk scoring engine (0–100 weighted model)
    ├── db.py                     # SQLite persistence & trend data retrieval
    │
    ├── parsers/                  # File-level parsers for VOLDEBUG collector output
    │   ├── system_info.py        # BIOS, ipconfig, hardware info
    │   ├── security.py           # BitLocker, Defender, EDR, firewall, credentials
    │   ├── software.py           # Installed software analysis & risk flagging
    │   ├── events.py             # Windows Event Log parsing & correlation
    │   ├── network.py            # Open ports, ARP table, DNS cache, connections
    │   └── persistence.py        # Registry run keys, scheduled tasks, services
    │
    └── reports/                  # Report generators
        ├── pdf_report.py         # Per-machine & fleet PDF reports (ReportLab)
        ├── excel_report.py       # Fleet Excel report (openpyxl)
        └── txt_report.py         # Plain text reports
```

## 🛠️ Tech Stack

* **Frontend:** Streamlit (interactive dashboard with custom CSS theming)
* **Visualization:** Plotly (donut charts, bar graphs, trend lines)
* **PDF Generation:** ReportLab + Matplotlib
* **Excel Reports:** openpyxl
* **Database:** SQLite (via built-in `db.py`)
* **Core Libraries:** Pandas, Jinja2, Pillow

## ⚙️ Setup & Installation

```bash
# 1. Navigate to the project folder
cd Report_Generation

# 2. Create and activate a virtual environment
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Linux/macOS

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the dashboard
streamlit run app.py
```

## 📊 Dashboard Pages

| Page | Purpose |
| :--- | :--- |
| **📁 Load & Analyze** | Point to a folder with VOLDEBUG audit data and trigger analysis |
| **🎯 Command Center** | Fleet risk overview — stat cards, risk distribution donut, machine risk bar chart, top findings |
| **🖥️ Machines** | Per-machine drill-down — system info, security posture badges, findings, persistence analysis |
| **🔎 Findings** | Filterable table of all findings across the fleet (severity, category, machine, keyword search) |
| **📊 Reports** | Download per-machine PDFs, fleet PDF/Excel/TXT, or a batch ZIP of all reports |
| **📈 Trends** | Historical audit run tracking with risk score trend charts |

## 🔐 Risk Scoring Methodology

Each machine receives a **0–100 risk score** using a weighted model:

- **CRITICAL** finding → +35 pts (capped at 2)
- **HIGH** finding → +20 pts (capped at 3)
- **MEDIUM** finding → +10 pts (capped at 5)
- **LOW** finding → +3 pts

Bonus multipliers apply for blind machines (no EDR/Defender), active compromise indicators, and servers/admin workstations. The system also escalates **compound risks** — e.g., Defender stopped + BitLocker off + AnyDesk installed = **CRITICAL**, not 3 separate findings.

## 📝 Status

✅ **Completed**

---
*Built by Aditya Maurya — Enterprise Security Audit Workflow*
