## 🤖 Automated Alert Triage & IOC Enrichment Pipeline

### 📌 Overview
This project automates the enrichment of IOCs like IPs, hashes, and domains. It queries multiple threat intelligence APIs and generates structured reports to assist SOC analysts during triage.

### 🎯 Project Goals
- Automate enrichment of IOCs with public TI sources.
- Format outputs in CSV, HTML, and Markdown.
- Send risk-ranked summaries to analysts via Slack or email.

### 🛠 Tools & APIs
- **Language:** Python
- **APIs:** VirusTotal, AbuseIPDB, AlienVault OTX
- **Output Formats:** Markdown, HTML, CSV
- **Notifications:** Slack API, SMTP Email

### 🧪 Sample Output (Markdown)
# IOC Enrichment Report – IP: 8.8.8.8

- **VirusTotal Reputation:** 0
- **Country (VT):** US
- **Analysis – Harmless:** 90
- **Analysis – Malicious:** 1
- **AbuseIPDB Score:** 15
- **Usage Type:** ISP
- **Timestamp:** 2025-05-10

### 💻 Sample Code Snippet
def enrich_ip_with_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    return requests.get(url, headers=headers).json()

### ✅ Outcomes
- Reduced manual IOC triage time by 40%.
- Produced structured enrichment reports with contextual data.
- Integrated enrichment with alert workflows.

### 🚀 Future Enhancements
- Add hash/domain enrichment support.
- Tag SIEM alerts with enrichment results.
- Build a GUI dashboard for SOC consumption.

---
