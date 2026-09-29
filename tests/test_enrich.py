from dataclasses import replace

import requests

from phishscan.enrich import EnrichmentResult, run_enrichment
from phishscan.enrich.abuseipdb import AbuseIPDB
from phishscan.enrich.cache import Cache, RateLimiter
from phishscan.enrich.urlscan import URLScan
from phishscan.enrich.virustotal import VirusTotal
from phishscan.extractor import IOCs
from tests.helpers import FakeResp, FakeSession

VT_OK = {"data": {"attributes": {"last_analysis_stats": {"malicious": 5, "harmless": 60, "suspicious": 0, "undetected": 5}}}}


def test_rate_limiter_sleeps_when_full():
    t, slept = [0.0], []
    lim = RateLimiter(2, 60, clock=lambda: t[0], sleep=lambda s: (slept.append(s), t.__setitem__(0, t[0] + s)))
    lim.wait(); lim.wait(); lim.wait()
    assert slept == [60]


def test_cache_roundtrip_and_ttl():
    t = [0.0]
    c = Cache(ttl=10, clock=lambda: t[0])
    c.set("k", {"a": 1})
    assert c.get("k") == {"a": 1}
    t[0] = 11
    assert c.get("k") is None


def test_virustotal_url_and_cache():
    s = FakeSession(FakeResp(200, VT_OK))
    vt = VirusTotal("key", session=s, cache=Cache())
    r = vt.check_url("http://evil.com/x")
    assert (r.malicious, r.total, r.error, r.kind) == (5, 70, None, "url")
    assert s.calls[0][1]["headers"]["x-apikey"] == "key"
    vt.check_url("http://evil.com/x")
    assert len(s.calls) == 1  # second call served from cache


def test_virustotal_not_found_is_clean_unknown():
    r = VirusTotal("k", session=FakeSession(FakeResp(404))).check_hash("a" * 64)
    assert r.malicious == 0 and r.error is None


def test_errors_never_raise():
    assert "rate limited" in VirusTotal("k", session=FakeSession(FakeResp(429))).check_ip("8.8.8.8").error
    assert "invalid API key" in VirusTotal("k", session=FakeSession(FakeResp(401))).check_ip("8.8.8.8").error
    r = VirusTotal("k", session=FakeSession(exc=requests.ConnectionError())).check_ip("8.8.8.8")
    assert "network error" in r.error


def test_abuseipdb_score():
    s = FakeSession(FakeResp(200, {"data": {"abuseConfidenceScore": 90}}))
    r = AbuseIPDB("k", session=s).check_ip("8.8.8.8")
    assert r.score == 90 and r.kind == "ip"


def test_urlscan_counts_malicious_verdicts():
    payload = {"results": [{"verdicts": {"overall": {"malicious": True}}}, {"verdicts": {"overall": {"malicious": False}}}, {}]}
    r = URLScan(session=FakeSession(FakeResp(200, payload))).check_domain("evil.com")
    assert r.malicious == 1 and r.total == 3


class Stub:
    def __init__(self, result):
        self.result = result

    def _as(self, kind):
        return replace(self.result, kind=kind)

    def check_url(self, x):
        return self._as("url")

    def check_hash(self, x):
        return self._as("hash")

    def check_ip(self, x):
        return self._as("ip")

    def check_domain(self, x):
        return self._as("domain")


def test_run_enrichment_findings():
    iocs = IOCs(["http://evil.com/x"], ["evil.com"], ["8.8.8.8"], [("a.exe", "a" * 64)])
    vt = Stub(EnrichmentResult("virustotal", "x", "url", malicious=5, total=70))
    ab = Stub(EnrichmentResult("abuseipdb", "8.8.8.8", "ip", score=95))
    us = Stub(EnrichmentResult("urlscan", "evil.com", "domain", malicious=1, total=3))
    results, findings = run_enrichment(iocs, {"virustotal": vt, "abuseipdb": ab, "urlscan": us})
    assert {f.rule for f in findings} == {"url_flagged", "ip_abuse", "attachment_malicious"}
    assert results


def test_run_enrichment_no_clients_is_empty():
    assert run_enrichment(IOCs(["http://a.com"], ["a.com"], [], []), {}) == ([], [])


def test_cache_and_limiter_usable_across_threads():
    import threading
    c = Cache()
    errors = []

    def work(n):
        try:
            for i in range(20):
                c.set(f"k{n}-{i}", {"v": i})
                assert c.get(f"k{n}-{i}") == {"v": i}
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    ts = [threading.Thread(target=work, args=(n,)) for n in range(4)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert errors == []


def test_build_clients_only_enables_configured_services():
    from phishscan.enrich import build_clients
    assert build_clients({}) == {}                       # no keys: nothing leaves the machine
    assert set(build_clients({"VT_API_KEY": "k"})) == {"virustotal"}
    assert set(build_clients({"URLSCAN_API_KEY": "k", "ABUSEIPDB_API_KEY": "k"})) == {"urlscan", "abuseipdb"}
