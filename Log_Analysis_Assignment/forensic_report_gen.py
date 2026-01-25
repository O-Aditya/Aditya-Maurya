import os
import requests
import json
import datetime
import sys
import time

# --- CONFIGURATION ---
BASE_DIR = "."
OUTPUT_DIR = os.path.join(BASE_DIR, "Final_Audit_Reports")
AUTHOR = "Aditya Maurya"

# Connection Settings
OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
MODEL_NAME = "mistral:latest" 

# Auto-detect log directory
LOG_DIR = None
for root, dirs, files in os.walk(BASE_DIR):
    if "raw_logs" in dirs: LOG_DIR = os.path.join(root, "raw_logs"); break
    if "raw_file" in dirs: LOG_DIR = os.path.join(root, "raw_file"); break
if not LOG_DIR: LOG_DIR = BASE_DIR

os.makedirs(OUTPUT_DIR, exist_ok=True)

# --- THE "AUDIT-GRADE" SYSTEM PROMPT ---
# This prompt forces the AI to mimic the structure of 'Cmdkey List Analysis Report.docx'
SYSTEM_PROMPT = f"""
You are a Senior Security Analyst & Digital Forensics Report Author.
Your task is to analyze a specific log artifact and write a formal, audit-grade report.

**STRICT OUTPUT FORMAT (PURE MARKDOWN):**

# [Artifact Name] Analysis Report
**Folder Name:** [Folder Name]
**File Types:** [Extension, e.g., CSV, TXT]
**Collection Date:** {datetime.datetime.now().strftime('%Y-%m-%d')}
**Report Generated:** {datetime.datetime.now().strftime('%Y-%m-%d')}

## 1. File Overview and Meaning
### 1.1 What Is the [Artifact Name]?
(Explain technical definition of this artifact in Windows/Linux environments.)

### 1.2 Purpose and Importance
(Explain why this data exists and why it is critical for security.)
* **Credential Discovery:** ...
* **Forensic Analysis:** ...

### 1.3 File Format and Structure
(Describe how the file is structured.)

## 2. Data Types and Structure
### 2.1 Key Attributes or Fields
(List common fields found in this type of artifact.)

### 2.2 Field Descriptions
| Field Name | Data Type | Description |
| :--- | :--- | :--- |
| [Field 1] | String/Int | [Description] |
| [Field 2] | String/Int | [Description] |

### 2.3 Sensitive or Security-Relevant Data Categories
* **Credential Metadata:** ...
* **Access Context:** ...

## 3. Where This Data Is Used
### 3.1 Security Operations Use Cases
(Explain how SOC teams use this data for auditing and monitoring.)

### 3.2 Incident Response and Threat Hunting
(Explain how IR teams use this to find attackers.)

### 3.3 Correlation With Other Artifacts
(List 2-3 other logs that correlate with this one, e.g., Event Logs, Firewall.)

## 4. Data Protection and Security Precautions
### 4.1 Why This Data Is Sensitive
(Explain risks if this data is leaked.)

### 4.2 Storage, Access Control, and Handling
* **Encryption:** ...
* **Access Control:** ...

### 4.3 Retention and Disposal Considerations
(Standard retention advice.)

## 5. Sample Findings and Anomalies
### 5.1 Normal or Expected Findings
(Describe what "Good" looks like.)

### 5.2 Suspicious or High-Risk Findings (ANALYSIS OF PROVIDED LOG)
(Analyze the ACTUAL CONTENT provided below. Use a table for findings.)
| Finding | Security Implication |
| :--- | :--- |
| [e.g., Cleartext Password] | [e.g., High-impact compromise] |
| [e.g., AnyDesk Detected] | [e.g., Unauthorized Remote Access] |
*(If clean, state: "No malicious indicators observed in this sample.")*

## 6. Executive Summary
(Write a professional summary of the analysis.)
**Data Sensitivity Level:** [High/Medium/Low]
**Protection Required:** [Encryption/Access Control]
**Forensic Value:** [High/Medium/Low]

---
**Report prepared by {AUTHOR}**
"""

def query_ollama_audit(filename, foldername, content):
    """Sends the log to Ollama with the Audit-Grade Prompt."""
    
    # Safety Truncation (4000 chars to prevent crashes)
    if len(content) > 4000:
        content_snippet = content[:4000] + "\n[...Truncated for Stability...]"
    else:
        content_snippet = content

    user_prompt = f"""
    Please generate the forensic report for the following file.
    
    FILE METADATA:
    - Filename: '{filename}'
    - Folder: '{foldername}'
    
    LOG CONTENT TO ANALYZE (For Section 5.2):
    {content_snippet}
    """

    payload = {
        "model": MODEL_NAME,
        "prompt": f"{SYSTEM_PROMPT}\n\n{user_prompt}",
        "stream": False,
        "options": {
            "temperature": 0.2,  # Low temp for professional tone
            "num_ctx": 4096,     # Sufficient context
            "num_predict": 1024  # Allow long reports
        }
    }

    try:
        session = requests.Session()
        session.trust_env = False 
        
        # 4 Minute timeout for detailed writing
        response = session.post(OLLAMA_URL, json=payload, timeout=240)
        
        if response.status_code == 500:
            return "❌ Error 500: Model overloaded."
        elif response.status_code == 404:
            return f"❌ Error 404: Model '{MODEL_NAME}' not found."
            
        response.raise_for_status()
        return response.json()['response']
        
    except Exception as e:
        return f"❌ Connection Error: {e}"

def main():
    print(f"\n🚀 Starting AUDIT-GRADE Analysis with {MODEL_NAME}...")
    
    count = 0
    
    for root, dirs, files in os.walk(LOG_DIR):
        for file in files:
            if file.endswith(".py") or file.startswith(".") or "Report" in file: continue
            
            filepath = os.path.join(root, file)
            folder_name = os.path.basename(root)
            
            print(f"🧠 Generating Report for: {file}...", end=" ", flush=True)
            
            try:
                with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                
                if not content.strip():
                    print("Skipped (Empty).")
                    continue

                ai_report = query_ollama_audit(file, folder_name, content)
                
                if "❌" in ai_report:
                    print(f"\n   {ai_report}")
                    time.sleep(2)
                    continue

                # Save
                out_name = f"Audit_Report_{file.replace('.', '_')}.md"
                with open(os.path.join(OUTPUT_DIR, out_name), "w", encoding="utf-8") as f:
                    f.write(ai_report)
                
                print("✅ Done.")
                count += 1
                
            except Exception as e:
                print(f"Error: {e}")

    print(f"\n🎉 Finished. {count} Audit-Grade reports saved in '{OUTPUT_DIR}'")

if __name__ == "__main__":
    main()