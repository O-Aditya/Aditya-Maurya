# Detailed Analysis Report
**Analyst:** Aditya Maurya
**Date:** 2026-01-22

## 1. Critical Finding: Credential Dump
**Severity:** CRITICAL
**Description:** Found AWS Access Key IDs exposed (likely in browser history/cache). This is a severe configuration error.
**Evidence:**
```text
browsers\Chrome\Default\History_copy.db
browsers\Chrome\Profile 12\History_copy.db
browsers\Chrome\Profile 13\History_copy.db
browsers\Chrome\Profile 14\History_copy.db
browsers\Chrome\Profile 16\History_copy.db
browsers\Chrome\Profile 17\History_copy.db
browsers\Chrome\Profile 6\History_copy.db
browsers\Chrome\Profile 8\History_copy.db
browsers\Edge\Default\History_copy.db
```

## 2. Web Log Analysis: SQL Injection
**Severity:** HIGH
**Description:** Detected suspicious usage of SELECT statements, potentially indicating SQL Injection attempts or malicious reconnaissance.
**Evidence:**
```text
risk_signals\powershell_operational_filtered.csv:    [string]$wql = "SELECT * FROM Win32_LogicalDisk WHERE MediaType=12"
risk_signals\powershell_operational_filtered.csv:    [string]$wql = "SELECT * FROM Win32_LogicalDisk WHERE MediaType=12 AND Name = '" + ${env:systemdrive} + "'"
risk_signals\powershell_operational_filtered.csv:   [WMI]$timeService = @(Get-WmiObject -Query "Select * From Win32_Service Where Name = `"$serviceName`"")[0]
```

## 3. System Log Analysis: Authentication Failures
**Severity:** MEDIUM
**Description:** Multiple failed access attempts detected.
**Evidence:**
```text
risk_signals\failed_logins.csv: "30-10-2025 03:22:50 PM","4625","-","-","127.0.0.1"
```
