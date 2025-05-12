import requests
import pandas as pd
import os
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
ABUSE_API_KEY = os.getenv("ABUSE_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")

def enrich_ip(ip):
    result = {"Type": "ip", "IOC": ip}
    # VirusTotal
    vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    vt_headers = {"x-apikey": VT_API_KEY}
    vt_r = requests.get(vt_url, headers=vt_headers)
    if vt_r.status_code == 200:
        d = vt_r.json()["data"]["attributes"]
        result.update({
            "VT_Reputation": d.get("reputation", "N/A"),
            "VT_Country": d.get("country", "N/A"),
            "VT_Malicious": d["last_analysis_stats"].get("malicious", 0)
        })

    # AbuseIPDB
    abuse_url = "https://api.abuseipdb.com/api/v2/check"
    abuse_headers = {"Accept": "application/json", "Key": ABUSE_API_KEY}
    abuse_params = {"ipAddress": ip, "maxAgeInDays": "90"}
    abuse_r = requests.get(abuse_url, headers=abuse_headers, params=abuse_params)
    if abuse_r.status_code == 200:
        a = abuse_r.json()["data"]
        result.update({
            "AbuseScore": a.get("abuseConfidenceScore", 0),
            "ISP": a.get("isp", "Unknown"),
            "Usage": a.get("usageType", "Unknown")
        })

    # OTX
    otx_url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    otx_headers = {"X-OTX-API-KEY": OTX_API_KEY}
    otx_r = requests.get(otx_url, headers=otx_headers)
    if otx_r.status_code == 200:
        o = otx_r.json()
        result["OTX_Pulses"] = len(o.get("pulse_info", {}).get("pulses", []))

    return result

def enrich_domain(domain):
    result = {"Type": "domain", "IOC": domain}
    # VirusTotal
    vt_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    vt_headers = {"x-apikey": VT_API_KEY}
    vt_r = requests.get(vt_url, headers=vt_headers)
    if vt_r.status_code == 200:
        d = vt_r.json()["data"]["attributes"]
        result.update({
            "VT_Reputation": d.get("reputation", "N/A"),
            "Registrar": d.get("registrar", "N/A"),
            "VT_Malicious": d["last_analysis_stats"].get("malicious", 0)
        })

    # OTX
    otx_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
    otx_headers = {"X-OTX-API-KEY": OTX_API_KEY}
    otx_r = requests.get(otx_url, headers=otx_headers)
    if otx_r.status_code == 200:
        o = otx_r.json()
        result["OTX_Pulses"] = len(o.get("pulse_info", {}).get("pulses", []))

    return result

def enrich_hash(file_hash):
    result = {"Type": "hash", "IOC": file_hash}
    vt_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}
    r = requests.get(vt_url, headers=headers)
    if r.status_code == 200:
        d = r.json()["data"]["attributes"]
        result.update({
            "Name": d.get("meaningful_name", "N/A"),
            "VT_Malicious": d["last_analysis_stats"].get("malicious", 0)
        })
    return result

def main():
    df = pd.read_csv("test_iocs.csv")
    results = []

    for _, row in df.iterrows():
        ioc = row["IOC"]
        ioc_type = row["Type"]

        if ioc_type == "ip":
            result = enrich_ip(ioc)
        elif ioc_type == "domain":
            result = enrich_domain(ioc)
        elif ioc_type == "hash":
            result = enrich_hash(ioc)
        else:
            result = {"Type": ioc_type, "IOC": ioc, "Error": "Unsupported IOC type"}

        result["Timestamp"] = datetime.now().isoformat()
        results.append(result)

    # Export to CSV
    pd.DataFrame(results).to_csv("ioc_enrichment_output.csv", index=False)

    # Export to Markdown
    with open("ioc_report.md", "w") as md:
        for r in results:
            md.write(f"## IOC: {r['IOC']}\n")
            for k, v in r.items():
                if k != "IOC":
                    md.write(f"- {k}: {v}\n")
            md.write("\n")

if __name__ == "__main__":
    main()
