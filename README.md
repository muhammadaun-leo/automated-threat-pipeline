# Automated Threat Intelligence & Malware Analysis Pipeline

An event-driven threat intelligence pipeline built in Python for automated binary ingestion, cryptographic hashing, YARA signature matching, and VirusTotal API enrichment.

## Features
- **Real-Time Monitoring**: Uses `watchdog` to monitor `incoming_samples/` for binary arrival.
- **Multi-Algorithm Hashing**: Generates MD5, SHA1, and SHA256 hashes upon file write completion.
- **Static Analysis**: Uses native YARA rules (`yara-python`) for offline signature matching.
- **Cloud Intelligence Integration**: Queries VirusTotal v3 REST API for community detection metrics.
- **Automated Archiving**: Exports structured JSON reports to `reports/` and quarantines analyzed files to `processed_samples/`.

## Project Structure
threat_pipeline/
├── incoming_samples/    # Monitored landing directory
├── processed_samples/   # Quarantine / archive directory
├── reports/             # JSON threat reports
├── rules/               # Custom YARA rules (.yar)
├── scripts/             # Master pipeline script
├── .env.example         # Template for environment variables
└── requirements.txt     # Python dependency list

