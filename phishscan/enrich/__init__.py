from ..extractor import defang
from ..weights import finding
from .abuseipdb import AbuseIPDB
from .base import EnrichmentResult
from .cache import RateLimiter
from .urlscan import URLScan
from .virustotal import VirusTotal

__all__ = ["EnrichmentResult", "build_clients", "run_enrichment"]

MAX_LOOKUPS = 10
_RULE = {"url": "url_flagged", "domain": "url_flagged", "ip": "ip_abuse", "hash": "attachment_malicious"}


def build_clients(env, cache=None):
    clients = {}
    if env.get("VT_API_KEY"):
        clients["virustotal"] = VirusTotal(env["VT_API_KEY"], cache=cache, limiter=RateLimiter(4, 60))
    if env.get("ABUSEIPDB_API_KEY"):
        clients["abuseipdb"] = AbuseIPDB(env["ABUSEIPDB_API_KEY"], cache=cache)
    clients["urlscan"] = URLScan(env.get("URLSCAN_API_KEY"), cache=cache)
    return clients


def run_enrichment(iocs, clients):
    vt, ab, us = clients.get("virustotal"), clients.get("abuseipdb"), clients.get("urlscan")
    results = []
    if vt:
        results += [vt.check_url(u) for u in iocs.urls[:MAX_LOOKUPS]]
        results += [vt.check_ip(i) for i in iocs.ips[:MAX_LOOKUPS]]
        results += [vt.check_hash(h) for _, h in iocs.hashes]
    if ab:
        results += [ab.check_ip(i) for i in iocs.ips[:MAX_LOOKUPS]]
    if us:
        results += [us.check_domain(d) for d in iocs.domains[:MAX_LOOKUPS]]
    findings = []
    for r in results:
        if r.error:
            continue
        min_hits = 1 if r.source == "urlscan" else 3
        if r.kind == "ip" and r.source == "abuseipdb":
            flagged = (r.score or 0) >= 50
            detail = f"abuse confidence {r.score}%"
        else:
            flagged = r.malicious >= min_hits
            detail = f"{r.malicious}/{r.total} detections"
        if flagged:
            findings.append(finding(_RULE[r.kind], f"{defang(r.indicator)} flagged by {r.source} ({detail})"))
    return results, findings
