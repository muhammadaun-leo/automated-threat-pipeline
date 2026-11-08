import os
import time
import json
import hashlib
import yara
from concurrent.futures import ThreadPoolExecutor
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from vt_enrich import check_virustotal

# Thread pool for non-blocking concurrent event processing
executor = ThreadPoolExecutor(max_workers=4)

WATCH_DIR = "incoming_samples"
PROCESSED_DIR = "processed_samples"
REPORTS_DIR = "reports"
YARA_RULES_PATH = "rules/malware_rules.yar"

# Compile YARA rules on startup
compiled_rules = None
if os.path.exists(YARA_RULES_PATH):
    try:
        compiled_rules = yara.compile(filepath=YARA_RULES_PATH)
    except Exception as e:
        print(f"[-] YARA compilation error: {e}")

def calculate_hashes(file_path):
    hashes = {}
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            
    hashes["md5"] = md5.hexdigest()
    hashes["sha1"] = sha1.hexdigest()
    hashes["sha256"] = sha256.hexdigest()
    return hashes

def scan_yara(file_path):
    if not compiled_rules:
        return []
    try:
        matches = compiled_rules.match(file_path)
        return [match.rule for match in matches]
    except Exception as e:
        print(f"[-] YARA scan error: {e}")
        return []

def process_sample(file_path):
    filename = os.path.basename(file_path)
    print(f"\n[+] Processing new sample: {filename}")
    
    # Brief pause to allow file buffer to flush completely
    time.sleep(0.5)
    
    if not os.path.exists(file_path):
        return
        
    try:
        # 1. Calculate Hashes
        hashes = calculate_hashes(file_path)
        print(f"  [>] SHA256: {hashes['sha256']}")
        
        # 2. Static YARA Rule Scan
        yara_matches = scan_yara(file_path)
        print(f"  [>] YARA Matches: {yara_matches}")
        
        # 3. VirusTotal Cloud Enrichment
        vt_data = check_virustotal(hashes['sha256'])
        
        # 4. Generate Structured JSON Report
        report = {
            "filename": filename,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "hashes": hashes,
            "yara_matches": yara_matches,
            "virustotal": vt_data
        }
        
        os.makedirs(REPORTS_DIR, exist_ok=True)
        report_path = os.path.join(REPORTS_DIR, f"{filename}_report.json")
        with open(report_path, "w") as rf:
            json.dump(report, rf, indent=4)
        print(f"  [+] Report saved: {report_path}")
        
        # 5. Quarantine Sample to Processed Directory
        os.makedirs(PROCESSED_DIR, exist_ok=True)
        dest_path = os.path.join(PROCESSED_DIR, filename)
        os.rename(file_path, dest_path)
        print(f"  [+] Sample moved to: {dest_path}")
        
    except Exception as e:
        print(f"[-] Error processing {filename}: {e}")

class CompletePipelineHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return
        # Dispatch file processing to thread pool (non-blocking)
        executor.submit(process_sample, event.src_path)

if __name__ == "__main__":
    os.makedirs(WATCH_DIR, exist_ok=True)
    event_handler = CompletePipelineHandler()
    observer = Observer()
    observer.schedule(event_handler, path=WATCH_DIR, recursive=False)
    observer.start()
    print(f"[*] Pipeline active. Monitoring directory '{WATCH_DIR}'...")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\n[*] Shutting down pipeline.")
    observer.join()
