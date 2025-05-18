#  Automated Alert Triage & IOC Enrichment Pipeline

##  Overview
This project is a Python-based enrichment pipeline that ingests IPs, domains, and hashes from security alerts and enriches them with contextual threat intelligence using open-source APIs. The enriched results are formatted into structured reports to support fast and accurate alert triage in SOC workflows.

---

##  Project Goals
- Automate enrichment of IOCs using VirusTotal, AbuseIPDB, and OTX
- Generate structured alert summaries in CSV, Markdown, and HTML
- Integrate alert notifications into Slack or Email
- Build a reusable enrichment module for SOC teams

---

##  Tools & APIs Used
- **Python** – Primary scripting language
- **VirusTotal API** – For file, domain, and IP enrichment
- **AbuseIPDB API** – For IP reputation scoring
- **AlienVault OTX API** – Additional threat context

---

##  Input Format
- Input can be provided via `.csv`, `.json`, or direct string list
- Example input:
```csv
IP,Type
8.8.8.8,ip
1.2.3.4,ip
```

---

##  Sample Enrichment Output (Markdown)
```markdown
# IOC Enrichment Report – IP: 8.8.8.8

- **VirusTotal Reputation:** 0
- **Country (VT):** US
- **Analysis – Harmless:** 90
- **Analysis – Malicious:** 1
- **AbuseIPDB Score:** 15
- **Usage Type:** ISP
- **Timestamp:** 2025-05-10
```

---

##  Enrichment Logic Example (Python)
```python
def enrich_ip_with_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    return requests.get(url, headers=headers).json()
```

---

##  Repository Artifacts
- `enrich_iocs.py` – Python script for running enrichment
- `test_iocs.csv` – Sample input list of indicators
- `ioc_enrichment_output.csv` – Enriched results
- `ioc_report.md` – Markdown summary
- `.env.example` - Create a .env file in the project root based on .env.example and add your API keys.

---

##  Outcomes
- Reduced manual enrichment workload by ~40%
- Delivered IOC context to analysts in seconds
- Created a reusable pipeline to plug into SIEM/SOAR platforms

---

##  Future Enhancements
- Build GUI front-end or Jupyter dashboard
- Integrate with SIEM tools for auto-tagging alerts
