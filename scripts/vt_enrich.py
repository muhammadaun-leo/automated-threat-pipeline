import json
import logging
import os
import requests
from dotenv import load_dotenv

# Load environment variables
BASE_DIR = os.path.expanduser("~/threat_pipeline")
load_dotenv(os.path.expanduser("~/threat_pipeline/.env"))
VT_API_KEY = os.getenv("VT_API_KEY")


REPORTS_DIR = os.path.join(BASE_DIR, "reports")
LOG_DIR = os.path.join(BASE_DIR, "logs")

logging.basicConfig(
    filename=os.path.join(LOG_DIR, "pipeline.log"),
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

def query_virustotal(file_hash):
    """Queries VirusTotal v3 API for a file hash."""
    if not VT_API_KEY or VT_API_KEY == "YOUR_API_KEY_HERE":
        print("[!] Error: Valid VT_API_KEY not found in .env file.")
        return None

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}

    print(f"[*] Querying VirusTotal for hash: {file_hash}...")
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        result = {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "harmless": stats.get("harmless", 0),
            "meaningful_name": attributes.get("meaningful_name", "Unknown"),
            "popular_threat_classification": attributes.get(
                "popular_threat_classification", {}
            ),
        }
        return result
    elif response.status_code == 404:
        print("[!] Hash not found in VirusTotal database.")
        return {"status": "not_found"}
    else:
        print(f"[!] VirusTotal API Error: {response.status_code}")
        return None

def enrich_reports():
    """Finds metadata reports and enriches them with VT intelligence."""
    for filename in os.listdir(REPORTS_DIR):
        if filename.endswith("_meta.json"):
            report_path = os.path.join(REPORTS_DIR, filename)

            with open(report_path, "r") as f:
                report_data = json.load(f)

            if "virustotal" in report_data:
                continue  # Already enriched

            sha256 = report_data["hashes"]["sha256"]
            vt_results = query_virustotal(sha256)

            if vt_results:
                report_data["virustotal"] = vt_results
                with open(report_path, "w") as f:
                    json.dump(report_data, f, indent=4)

                print(f"[+] Enriched report: {report_path}")
                if "malicious" in vt_results:
                    print(
                        f"[+] Detections: {vt_results['malicious']} AV engines flagged this sample."
                    )

if __name__ == "__main__":
    enrich_reports()
