import hashlib
import json
import logging
import os
import shutil
import time
from datetime import datetime
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

# Base directory paths
BASE_DIR = os.path.expanduser("~/threat_pipeline")
LOG_DIR = os.path.join(BASE_DIR, "logs")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
PROCESSED_DIR = os.path.join(BASE_DIR, "processed_samples")
WATCH_DIR = os.path.join(BASE_DIR, "incoming_samples")

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(PROCESSED_DIR, exist_ok=True)

logging.basicConfig(
    filename=os.path.join(LOG_DIR, "pipeline.log"),
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

def calculate_hashes(file_path):
    """Calculates MD5, SHA1, and SHA256 hashes of a file."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }

class SampleHandler(FileSystemEventHandler):
    """Monitors directory for new incoming suspicious files."""

    def on_created(self, event):
        if event.is_directory:
            return

        file_path = event.src_path
        filename = os.path.basename(file_path)

        time.sleep(1)  # Allow file write completion

        if not os.path.exists(file_path):
            return

        print(f"\n[+] New File Detected: {filename}")
        logging.info(f"Processing incoming sample: {filename}")

        hashes = calculate_hashes(file_path)
        file_size = os.path.getsize(file_path)

        metadata = {
            "filename": filename,
            "timestamp": datetime.utcnow().isoformat(),
            "size_bytes": file_size,
            "hashes": hashes,
            "status": "ingested",
        }

        report_path = os.path.join(REPORTS_DIR, f"{hashes['sha256']}_meta.json")
        with open(report_path, "w") as f:
            json.dump(metadata, f, indent=4)

        print(f"[+] Computed SHA256: {hashes['sha256']}")
        print(f"[+] Saved Initial Metadata: {report_path}")

        dest_path = os.path.join(PROCESSED_DIR, filename)
        shutil.move(file_path, dest_path)
        print(f"[+] Moved Sample to: {dest_path}")
        logging.info(f"Sample {filename} moved to processed_samples.")

if __name__ == "__main__":
    print("[*] Threat Intelligence Watcher Active...")
    print(f"[*] Monitoring directory: {WATCH_DIR}")

    event_handler = SampleHandler()
    observer = Observer()
    observer.schedule(event_handler, WATCH_DIR, recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\n[*] Stopping Watcher Service.")
    observer.join()
