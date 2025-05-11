# 🤖 Automated Alert Triage & IOC Enrichment Pipeline

## 📌 Overview

This project automates the enrichment of indicators of compromise (IOCs), such as IP addresses, domains, and hashes. The script queries public threat intelligence APIs (VirusTotal, OTX, AbuseIPDB) and formats the results into actionable reports, helping SOC analysts reduce triage time and make faster decisions.

---

## 🎯 Goals

- Enrich IOCs using real-time threat intelligence
- Automate report generation (CSV, Markdown, HTML)
- Provide risk scoring and metadata for faster triage
- Integrate alert notifications via email or Slack

---

## 🧰 Tools & APIs Used

- **Language:** Python  
- **Threat Intel APIs:** VirusTotal, AbuseIPDB, AlienVault OTX  
- **Output Formats:** CSV, Markdown, HTML  
- **Alerting (optional):** Slack API, SMTP Email  

---
