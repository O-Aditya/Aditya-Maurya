# 🛡️ Cybersecurity Forensic Dashboard

A full-stack Incident Response & Forensic Audit System designed to analyze, visualize, and report on system security artifacts. This project utilizes a **Microservices Architecture** with a FastAPI backend for data processing and a Streamlit frontend for an interactive analyst dashboard.

---

## 🚀 Features

### 🧠 Backend API (server.py)

- **Automated Parsing**: Reads raw Markdown audit reports and extracts key metadata (Risk Level, Forensic Value, Executive Summary)
- **RESTful Endpoints**: Serves structured JSON data to the frontend or external tools
- **Performance**: Built on FastAPI for high-performance, asynchronous data serving

### 💻 Analyst Dashboard (dashboard.py)

- **Real-Time APIs**: Instant view of Total Files Scanned, Critical Threats, and Secure Artifacts
- **Priority Alerts**: Red "Action Required" banners for high-risk findings
- **Interactive Visualization**:
  - 📊 **Threat Landscape**: Bar chart showing risk distribution (High vs. Medium vs. Low)
  - 🍩 **Evidence Value**: Donut chart breaking down artifacts by forensic importance
- **Search & Filter**: Instant full-text search across filenames and report contents
- **Report Viewer**:
  - Pop-up Modal: Read full reports without leaving the dashboard
  - Download: One-click download for individual `.md` reports or a full `.csv` summary of all findings

---

## 📂 Project Structure

```
GUI_Assignment/
├── dashboard.py                    # Frontend (Streamlit)
├── server.py                       # Backend (FastAPI)
├── requirements.txt                # Project Dependencies
├── README.md                       # Project Documentation
│
├── Report/                         # Folder containing AI-generated .md reports
│   ├── Audit_Report_bitlocker_status_txt.md
│   ├── Audit_Report_defender_status_txt.md
│   ├── Audit_Report_firewall_profiles_txt.md
│   └── ...
│
└── Raw_Logs/                       # Raw system data files
    ├── bitlocker_status.txt
    ├── defender_status.txt
    ├── firewall_profiles.txt
    └── ...
```

---

## 🛠️ Installation & Setup

### Prerequisites

- Python 3.8 or higher
- Pip (Python Package Manager)

### 1. Install Dependencies

Navigate to the project folder and run:

```bash
pip install -r requirements.txt
```

### 2. Run the Application

You need to run both the API backend and the Dashboard frontend.

#### Option A: The Professional Way (Two Terminals)

**Terminal 1 (Backend):**
```bash
uvicorn server:app --reload
```

**Terminal 2 (Frontend):**
```bash
streamlit run dashboard.py
```

#### Option B: The "One-Click" Way (Windows)

Create a file named `run_system.bat` with the following code:

```batch
@echo off
start cmd /k "uvicorn server:app --host 127.0.0.1 --port 8000"
timeout /t 3
start cmd /k "streamlit run dashboard.py"
```

Double-click `run_system.bat` to launch everything.

---

## 📡 API Documentation

Once `server.py` is running, full interactive documentation is available at:

```
http://127.0.0.1:8000/docs
```

### Available Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/stats` | Returns aggregated metrics (Total files, Risk counts) |
| GET | `/reports` | Lists all reports with metadata (Title, Risk, Summary) |
| GET | `/reports/{filename}` | Returns the full Markdown content of a specific report |

---

## ☁️ Deployment Guide (Streamlit Cloud)

To deploy this microservice architecture on Streamlit Cloud:

1. **Structure**: Ensure `requirements.txt` is in the root of your GitHub repository
2. **Config**: In `dashboard.py`, ensure the `start_api_server()` function uses `cwd=os.path.dirname(...)` to find the server file correctly
3. **Deploy**:
   - Go to [Streamlit Cloud](https://streamlit.io/cloud)
   - Select your repository
   - Set Main file path to `GUI_Assignment/dashboard.py`
   - Click Deploy

---

## 🔮 Future Improvements

- **Authentication**: Add a login page for authorized SOC analysts
- **Database Integration**: Move from file-based storage (`.md` files) to SQLite/PostgreSQL
- **Live Scanning**: Add a button to trigger the Python collector script directly from the GUI
- **Export Formats**: Support additional export formats (PDF, JSON, XML)
- **Advanced Filtering**: Implement date range filters and risk-based sorting

---

## 📋 Requirements

See `requirements.txt` for all dependencies. Key packages include:

- `fastapi` - Backend API framework
- `streamlit` - Frontend dashboard framework
- `uvicorn` - ASGI server for FastAPI
- `pandas` - Data manipulation and CSV handling
- `markdown` - Markdown parsing

---

## 👤 Author

**Aditya Maurya**

---

## 📝 License

This project is provided as-is for educational and forensic analysis purposes.

---

## 📞 Support

For issues or questions, please refer to the project documentation or contact the development team.