# Security policy

## Reporting a vulnerability
Please report security issues privately (for example through GitHub's "Report a vulnerability" feature on this repository) rather than opening a public issue. Include steps to reproduce and the affected version (`phishscan --version`). You can expect an acknowledgement within a few days.

## Design notes
- Untrusted input: PhishScan parses attacker-controlled email. It never executes or opens attachments, never fetches URLs, and HTML-escapes everything it renders. Reports contain no JavaScript.
- The web app processes uploads in memory, caps upload size, rate limits per client IP and sends a strict Content-Security-Policy. It has **no authentication**; do not expose it to the public internet without an authenticating reverse proxy.
- Secrets: API keys are read from environment variables or a git-ignored `.env`. Never commit `.env`.
- Privacy: when reputation lookups are enabled, indicators (URLs, domains, IPs, file hashes) are sent to VirusTotal, AbuseIPDB and URLScan. Email bodies are never sent.
- Containers run as a non-root user; the provided compose file also uses a read-only root filesystem and drops all capabilities.
