from phishscan.analyzer import analyze
from phishscan.enrich import EnrichmentResult

PASS = "mx; spf=pass; dkim=pass; dmarc=pass"


def test_clean_email_is_safe(write_eml):
    a = analyze(write_eml(auth=PASS))
    assert a.verdict.label == "Safe" and a.verdict.score == 0
    assert any("skipped" in n.lower() for n in a.notes)


def test_spoofed_phish_is_malicious(write_eml):
    a = analyze(write_eml(from_="PayPal Support <support@paypa1.com>",
                          auth="mx; spf=fail; dkim=fail; dmarc=fail",
                          text="URGENT verify your account immediately http://bit.ly/x"))
    assert a.verdict.label == "Malicious"
    assert ("T1566.002", "Phishing: Spearphishing Link") in a.techniques


def test_middle_is_suspicious(write_eml):
    a = analyze(write_eml(auth="mx; spf=fail; dkim=pass; dmarc=pass", reply_to="x@evil.com"))
    assert a.verdict.label == "Suspicious"


class Failing:
    def check_url(self, x):
        return EnrichmentResult("virustotal", x, "url", error="virustotal: rate limited")

    check_ip = check_hash = check_domain = check_url


def test_enrichment_errors_become_notes(write_eml):
    a = analyze(write_eml(auth=PASS, text="see http://evil.com/x"), {"virustotal": Failing()})
    assert a.verdict.label == "Safe"
    assert any("rate limited" in n for n in a.notes)
