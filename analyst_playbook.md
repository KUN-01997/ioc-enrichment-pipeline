# 📘 IOC Enrichment Pipeline – Analyst Playbook

## 🎯 Purpose

This playbook outlines how SOC analysts should use the Automated IOC Enrichment Pipeline to triage alerts that contain raw indicators such as IPs, domains, or file hashes. The pipeline provides contextual enrichment and risk scoring using open-source intelligence sources.

---

## 🧪 Use Cases

- Triage a suspicious IP from a phishing email alert
- Validate external connections from a critical host
- Confirm reputation of an outbound connection flagged by EDR

---

## 🛠 How to Use

1. Place raw IOCs in `test_iocs.csv` with headers:
   ```
   IOC,Type
   8.8.8.8,ip
   evil.com,domain
   ```

2. Run the enrichment script:
   ```
   python enrich_iocs.py
   ```

3. Review output:
   - `ioc_enrichment_output.csv`
   - `ioc_report.md`
   - (Optional) `ioc_report.html`

4. Forward high-risk entries to Tier 3 or IR team if:
   - VT score > 3 malicious engines
   - AbuseIPDB confidence > 50
   - Associated domain is blacklisted or sandbox flagged

---

## 🧠 Threat Intel Sources

- **VirusTotal**: 90+ AV engines and IP/domain sandboxing
- **AbuseIPDB**: Crowdsourced IP reputation database
- **OTX**: AlienVault Open Threat Exchange for global indicators

---

## ✅ Analyst Outcome

You should be able to:
- Identify benign vs. high-confidence malicious IOCs
- Document indicators into the IR case
- Reduce manual lookups and response time
