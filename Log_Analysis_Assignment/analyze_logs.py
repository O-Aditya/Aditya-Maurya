import os
import re
import datetime

# --- CONFIGURATION ---
BASE_DIR = "."
LOG_DIR = os.path.join(BASE_DIR, "raw_logs")
DOC_DIR = os.path.join(BASE_DIR, "docs")
REPORTS_DIR = os.path.join(DOC_DIR, "file_reports")  # Folder for individual file reports
SUMMARY_FILE = os.path.join(DOC_DIR, "Executive_Summary.md")

# Ensure directories exist
os.makedirs(REPORTS_DIR, exist_ok=True)

# --- SECURITY RULES & RISK SCORING [cite: 50, 54] ---
# Higher weights = more severe threats
RULES = [
    {
        "name": "AWS Credential Leakage",
        "regex": re.compile(rb"AKIA[0-9A-Z]{16}"), # Binary safe for DB files
        "score": 100,
        "severity": "CRITICAL",
        "desc": "AWS Access Key ID detected. Immediate rotation required."
    },
    {
        "name": "SQL Injection Pattern",
        "regex": re.compile(r"(UNION\s+SELECT|DROP\s+TABLE|OR\s+1=1)", re.IGNORECASE),
        "score": 50,
        "severity": "HIGH",
        "desc": "Potential SQL Injection attempt detected in query parameters."
    },
    {
        "name": "PowerShell Reconnaissance",
        "regex": re.compile(r"SELECT.*FROM\s+Win32", re.IGNORECASE),
        "score": 30,
        "severity": "HIGH",
        "desc": "System information discovery using PowerShell WMI queries."
    },
    {
        "name": "Brute Force / Auth Failure",
        "regex": re.compile(r"(Failed password|Access denied|EventCode=4625)", re.IGNORECASE),
        "score": 10,
        "severity": "MEDIUM",
        "desc": "Repeated authentication failures detected."
    }
]

def analyze_file(filepath):
    """Analyzes a single file and returns findings + risk score [cite: 53]"""
    findings = []
    total_score = 0
    file_severity = "LOW"
    
    try:
        with open(filepath, "rb") as f:
            content_bin = f.read()
            
            # Decoded content for text-based checks
            try:
                content_text = content_bin.decode("utf-8", errors="ignore")
            except:
                content_text = ""

            # Check every rule against the file
            for rule in RULES:
                hit = False
                # Binary check for Keys, Text check for others
                if "AKIA" in rule["regex"].pattern.decode() if isinstance(rule["regex"].pattern, bytes) else False:
                    if rule["regex"].search(content_bin):
                        hit = True
                else:
                    if rule["regex"].search(content_text):
                        hit = True
                
                if hit:
                    findings.append(rule)
                    total_score += rule["score"]

        # Determine overall File Severity [cite: 55]
        if total_score >= 100: file_severity = "CRITICAL"
        elif total_score >= 50: file_severity = "HIGH"
        elif total_score >= 10: file_severity = "MEDIUM"

        return findings, total_score, file_severity

    except Exception as e:
        print(f"Error reading {filepath}: {e}")
        return [], 0, "ERROR"

def generate_file_report(filename, filepath, findings, score, severity):
    """Generates a dedicated Markdown report for a single log file [cite: 36, 57]"""
    report_name = f"Report_{filename.replace('.', '_')}.md"
    report_path = os.path.join(REPORTS_DIR, report_name)
    
    with open(report_path, "w",encoding="utf-8") as f:
        f.write(f"# Security Analysis: {filename}\n")
        f.write(f"**Date:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
        f.write(f"**Source Path:** `{filepath}`\n")
        f.write(f"**Risk Score:** {score} / 100\n")
        f.write(f"**Risk Level:** {severity}\n\n") # [cite: 60]
        
        f.write("## 📊 Summary of Findings\n")
        if not findings:
            f.write("✅ No significant security threats detected.\n")
        else:
            f.write("| Detected Threat | Severity | Description |\n")
            f.write("| :--- | :--- | :--- |\n")
            for item in findings:
                f.write(f"| {item['name']} | **{item['severity']}** | {item['desc']} |\n")
        
        f.write("\n## 📝 Recommendations\n")
        if severity == "CRITICAL":
            f.write("- 🔴 **Immediate Action:** Revoke exposed credentials and isolate the host.\n")
        elif severity == "HIGH":
            f.write("- 🟠 **Investigate:** Check source IPs and block malicious traffic.\n")
        else:
            f.write("- 🟢 **Monitor:** Keep under standard observation.\n")

    return report_name

def main():
    print("🚀 Starting Automated Log Analysis[cite: 32]...")
    summary_data = []

    # Iterate through all files recursively 
    for root, _, files in os.walk(LOG_DIR):
        for file in files:
            filepath = os.path.join(root, file)
            print(f"   -> Analyzing: {file}...")
            
            # Analyze
            findings, score, severity = analyze_file(filepath)
            
            # Generate Individual Report if risks found (or for all if preferred)
            # We generate for ALL to meet the 'separate reports for each log file' requirement 
            report_link = generate_file_report(file, filepath, findings, score, severity)
            
            summary_data.append({
                "file": file,
                "score": score,
                "severity": severity,
                "report": report_link
            })

    # Generate Master Executive Summary
    print("📋 Generating Executive Summary...")
    with open(SUMMARY_FILE, "w" ,encoding="utf-8") as f:
        f.write("# 🛡️ Automated Security Analysis Summary\n")
        f.write("This document provides an index of all analyzed log files and their security status.\n\n")
        f.write("| Log File | Risk Score | Risk Level | Detailed Report |\n")
        f.write("| :--- | :--- | :--- | :--- |\n")
        
        # Sort by Risk Score (Highest first) for better visibility
        summary_data.sort(key=lambda x: x["score"], reverse=True)
        
        for item in summary_data:
            icon = "🟢"
            if item["severity"] == "CRITICAL": icon = "🔴"
            elif item["severity"] == "HIGH": icon = "🟠"
            elif item["severity"] == "MEDIUM": icon = "🟡"
            
            f.write(f"| `{item['file']}` | {item['score']} | {icon} {item['severity']} | [View Report](./file_reports/{item['report']}) |\n")

    print(f"✅ Analysis Complete. Reports generated in '{REPORTS_DIR}'")

if __name__ == "__main__":
    main()