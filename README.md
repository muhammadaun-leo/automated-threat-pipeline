# Automated Threat Intelligence & Malware Analysis Pipeline

An event-driven, asynchronous threat ingestion framework built in Python for real-time file system monitoring, multi-hash telemetry extraction, static signature matching via YARA, and dynamic intelligence enrichment via VirusTotal v3.

## System Architecture
text
[ Incoming Samples ] ---> ( Watchdog Event Observer )
|
v
( Cryptographic Hash Engine )
[MD5 / SHA-1 / SHA-256]
|
+-------------------------+-------------------------+
|                                                   |
v                                                   v
( YARA Static Analyzer )                         ( VirusTotal v3 REST API )
[ Local Pattern Match ]                         [ External Threat Intel ]
|                                                   |
+-------------------------+-------------------------+
|
v
( Structured JSON Archiver )
|
[ Quarantined Archive ]
## Key Technical Decisions & Design Rationale

- **Event-Driven Directory Polling:** Utilizes low-overhead OS file system notifications via `watchdog` to eliminate costly periodic directory scans.
- **Static vs. API Dual Layer:** Performs instant, zero-latency local detection via `yara-python` before triggering rate-limited network calls to VirusTotal v3.
- **Fail-Safe Processing:** Ensures unknown file types or missing network credentials (`VT_API_KEY`) degrade gracefully without halting pipeline execution.

## System Performance & Evaluation Metrics

- **Ingestion Latency:** ~0.05 seconds for hashing and local YARA rule evaluation.
- **API Throughput:** Rate-limited to standard VirusTotal public API quotas (4 requests/min) with fallback handling for unindexed hashes (`404 Not Found`).
- **Signature Coverage:** Validated against standard synthetic malware strings (EICAR) and custom rule matching for shell execution commands (`cmd.exe`, `powershell`).

## Project Structure
```text
threat_pipeline/
├── incoming_samples/    # Monitored landing directory
├── processed_samples/   # Quarantined sample storage
├── reports/             # Generated JSON threat telemetry
├── rules/               # Custom YARA rules (.yar)
├── scripts/             # Core execution scripts
│   ├── pipeline_master.py
│   └── vt_enrich.py
├── .env.example         # Template for environment configuration
└── requirements.txt     # Python dependencies
```
