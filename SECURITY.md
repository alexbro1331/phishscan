# Security policy

## Reporting a vulnerability
Please report security issues privately (for example through GitHub's "Report a vulnerability" feature on this repository) rather than opening a public issue. Include steps to reproduce and the affected version (`phishscan --version`). You can expect an acknowledgement within a few days.

## Design notes
- **Hostile input.** PhishScan parses attacker-controlled email. It never executes or opens attachments, never fetches URLs, and HTML-escapes everything it renders. Downloaded reports contain no JavaScript.
- **Access control.** The web console supports a password (`PHISHSCAN_PASSWORD`). It refuses to listen on a network address without one unless you explicitly set `PHISHSCAN_ALLOW_NO_AUTH=1`. Login is rate limited and constant-time; sessions use HttpOnly, SameSite=Lax cookies (add `PHISHSCAN_COOKIE_SECURE=1` behind HTTPS). It is a single shared password, not per-user accounts.
- **CSRF and headers.** Every state-changing request needs a CSRF token. Responses carry a strict Content-Security-Policy (scripts only from the server itself), `X-Frame-Options: DENY`, `nosniff` and `no-store`.
- **Abuse limits.** Upload size is capped and requests are rate limited per client IP. `/api/*` needs a Bearer token when a password is set.
- **Stored data.** The message body is never stored. A case keeps the analysis result (subject, addresses, headers, indicators, verdict) and analyst notes in a local SQLite file. Use `PHISHSCAN_RETENTION_DAYS` to auto-delete, `PHISHSCAN_MEMORY_ONLY=1` to store nothing on disk, and the Settings page to delete everything. Protect the database file and its volume like the sensitive data it may contain.
- **Secrets.** API keys and the password are read from environment variables or a git-ignored `.env`. Never commit `.env`.
- **Privacy of lookups.** With no API keys configured, nothing leaves the machine. When you configure a lookup service, indicators (URLs, domains, IPs, file hashes) are sent to that service; email text never is.
- **Containers.** The image runs as a non-root user; the provided compose file also uses a read-only root filesystem and drops all capabilities.
