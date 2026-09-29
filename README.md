# PhishScan: automated phishing email triage

Analyze a suspicious email (`.eml`) in seconds and get an **explainable** verdict (Safe / Suspicious / Malicious), an HTML report, and MITRE ATT&CK mapping.

## Why
Phishing triage is the most repetitive SOC task. An analyst spends roughly 10-15 minutes per email checking headers, extracting links, and looking things up. PhishScan does the same first-pass in seconds and shows *why* it reached its verdict, so the analyst can trust or override it.

## Features
- Header analysis: SPF / DKIM / DMARC results, From vs Reply-To / Return-Path mismatch, display-name spoofing.
- Content heuristics: lookalike sender domains (`paypa1.com`), URL shorteners, raw-IP links, urgency language, risky attachment types (including double extensions like `invoice.pdf.exe`).
- IOC extraction: URLs, domains, public IPs (including from `Received` headers), attachment SHA256.
- Reputation lookups (optional): VirusTotal, AbuseIPDB, URLScan, with a local SQLite cache and a 4 requests/minute limiter for VirusTotal's free tier.
- **Explainable score**: every point in the 0-100 score has a stated reason.
- MITRE ATT&CK mapping and recommended response actions in the report.
- Works fully offline (`--offline`); API failures never crash a run, they appear as notes in the report.

## Architecture
```
.eml -> parser -> auth checks ----------\
              \-> extractor (IOCs) -> heuristics --> scorer --> report (HTML/JSON)
                          \-> enrichment (VT / AbuseIPDB / URLScan, cached) --/
```
Modules live in `phishscan/`; each has one job and its own tests in `tests/`.

## Install
```bash
python -m venv .venv
.venv/Scripts/activate        # Windows (Linux/macOS: source .venv/bin/activate)
pip install -r requirements.txt
cp .env.example .env          # then add your free API keys
```
Free keys: [virustotal.com](https://www.virustotal.com), [abuseipdb.com](https://www.abuseipdb.com), [urlscan.io](https://urlscan.io). All are optional.

## Usage
```bash
python -m phishscan examples/phishing.eml            # HTML report next to the .eml
python -m phishscan examples/phishing.eml --offline  # no network
python -m phishscan examples/phishing.eml --json -o out/report.html
```
Exit codes: `0` Safe, `1` Suspicious, `2` Malicious, `3` file not found. This makes it easy to use in scripts or a mail pipeline.

Sample output (offline):
```
Verdict: Malicious (score 100/100)
  +25  DMARC result: fail
  +25  Attachment 'invoice.pdf.exe' has a risky file type (.exe)
  +25  Sender domain 'paypa1.com' imitates the brand 'paypal'
  ...
  IOC: hxxp://bit[.]ly/3xYz
```
Open `examples/phishing.report.html` in a browser to see the full report.

## Scoring
Weights live in one place, [`phishscan/weights.py`](phishscan/weights.py). Each rule counts once; score is capped at 100. **0-29 Safe, 30-59 Suspicious, 60+ Malicious.**

| Rule | Points | Rule | Points |
|---|---|---|---|
| Attachment malicious (hash) | 50 | Display-name spoof | 20 |
| URL flagged by engines | 40 | IP high abuse score | 20 |
| DMARC fail | 25 | SPF / DKIM fail | 15 each |
| Lookalike domain | 25 | Reply-To mismatch | 15 |
| Risky attachment type | 25 | IP-literal URL | 15 |
| No auth header | 10 | Shortener / urgency / Return-Path mismatch | 10 each |

## Safety
- Attachments are **hashed only**; never opened or executed.
- Links are **never visited**; only looked up by URL/hash/IP.
- All IOCs are **defanged** (`hxxp://evil[.]com`) in reports and console output.
- API keys come from `.env` (git-ignored). No email content is stored; only API lookups are cached by indicator.

## Tests
```bash
python -m pytest -q
```
No internet or API keys needed (HTTP is mocked).

## Limitations / next steps
- Weights are heuristics; tune them against your own mail.
- SPF/DKIM/DMARC come from the receiving server's `Authentication-Results` header and are not re-verified.
- URLScan lookups use the public search API; result fields may need adjusting against live data.
- Ideas: batch mode for a folder of emails, `.msg` support, Streamlit UI, a MISP/TheHive export.
