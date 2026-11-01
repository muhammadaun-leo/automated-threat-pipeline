import hashlib
import json
import logging
import os
import shutil
import time
from datetime import datetime, timezone
from dotenv import load_dotenv
import requests
import yara
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

BASE_DIR = os.path.expanduser("~/threat_pipeline")
LOG_DIR = os.path.join(BASE_DIR, "logs")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
PROCESSED_DIR = os.path.join(BASE_DIR, "processed_samples")
WATCH_DIR = os.path.join(BASE_DIR, "incoming_samples")
RULES_FILE = os.path.join(BASE_DIR, "rules", "malware_rules.yar")

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(PROCESSED_DIR, exist_ok=True)

load_dotenv(os.path.join(BASE_DIR, ".env"))
VT_API_KEY = os.getenv("VT_API_KEY")

compiled_rules = yara.compile(filepath=RULES_FILE) if os.path.exists(RULES_FILE) else None

def calculate_hashes(file_path):
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}

def scan_yara(file_path):
    if not compiled_rules:
        return []
    matches = compiled_rules.match(file_path)
    return [match.rule for match in matches]

def query_vt(sha256):
    if not VT_API_KEY:
        return {"status": "no_key"}
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": VT_API_KEY}
    res = requests.get(url, headers=headers)
    if res.status_code == 200:
        stats = res.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {"malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0), "undetected": stats.get("undetected", 0)}
    return {"status": "not_found" if res.status_code == 404 else "api_error"}

class CompletePipelineHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return
        file_path = event.src_path
        filename = os.path.basename(file_path)
        time.sleep(1)

        if not os.path.exists(file_path):
            return

        print(f"\n[+] Ingested New File: {filename}")
        hashes = calculate_hashes(file_path)
        print(f"[+] SHA256: {hashes['sha256']}")

        yara_matches = scan_yara(file_path)
        print(f"[+] YARA Rule Matches: {yara_matches}")

        vt_intel = query_vt(hashes["sha256"])
        print(f"[+] VirusTotal Detections: {vt_intel}")

        metadata = {
            "filename": filename,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "size_bytes": os.path.getsize(file_path),
            "hashes": hashes,
            "yara_matches": yara_matches,
            "virustotal": vt_intel,
        }

        report_path = os.path.join(REPORTS_DIR, f"{hashes['sha256']}_report.json")
        with open(report_path, "w") as f:
            json.dump(metadata, f, indent=4)

        dest_path = os.path.join(PROCESSED_DIR, filename)
        shutil.move(file_path, dest_path)
        print(f"[+] Complete Threat Intel Report archived to: {report_path}")

if __name__ == "__main__":
    print("[*] Complete Threat Pipeline with YARA Engine Active...")
    event_handler = CompletePipelineHandler()
    observer = Observer()
    observer.schedule(event_handler, WATCH_DIR, recursive=False)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
