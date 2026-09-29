import json

from phishscan.analyzer import analyze
from phishscan.report import render_html, render_json


def test_html_report_content_and_defang(write_eml):
    a = analyze(write_eml(from_="PayPal <s@paypa1.com>", auth="mx; spf=fail; dkim=fail; dmarc=fail",
                          text="URGENT verify your account immediately http://evil.com/login"))
    html = render_html(a)
    assert "Malicious" in html and "hxxp://evil[.]com/login" in html
    assert "http://evil.com/login" not in html
    assert "T1566.002" in html or "T1672" in html


def test_html_escapes_untrusted_fields(write_eml):
    a = analyze(write_eml(subject="<script>alert(1)</script>", from_='"<img src=x onerror=alert(1)>" <a@b.com>'))
    html = render_html(a)
    assert "<script>alert(1)</script>" not in html and "<img src=x" not in html


def test_json_report(write_eml):
    data = json.loads(render_json(analyze(write_eml(auth="mx; spf=fail; dkim=pass; dmarc=pass"))))
    assert data["verdict"]["label"] == "Safe" and data["verdict"]["score"] == 15
    assert data["verdict"]["findings"][0]["rule"] == "spf_fail"


def _phish(write_eml, **kw):
    base = dict(from_="PayPal <s@paypa1.com>", auth="mx; spf=fail; dkim=fail; dmarc=fail",
                subject="Account suspended", text="URGENT verify your account immediately",
                html='<a href="http://evil.com/x">https://www.paypal.com/login</a>',
                received=["from mail.evil.ru (mail.evil.ru [8.8.8.8]) by mx.google.com; Mon, 1 Jan 2024 10:00:00 +0000"],
                attachments=[("invoice.pdf.exe", b"MZ")])
    base.update(kw)
    return analyze(write_eml(**base))


def test_report_has_no_javascript_and_key_sections(write_eml):
    html = render_html(_phish(write_eml))
    assert "<script" not in html.lower()
    for section in ("Verdict", "Why this verdict", "Email authentication", "Mail route",
                    "Attachments", "Indicators of compromise", "MITRE ATT&amp;CK", "Recommended actions"):
        assert section in html, section


def test_report_shows_route_attachment_and_link_finding(write_eml):
    a = _phish(write_eml)
    html = render_html(a)
    assert "mail[.]evil[.]ru" in html or "mail.evil.ru" in html
    assert "8[.]8[.]8[.]8" in html
    assert "invoice.pdf.exe" in html and a.email.attachments[0].sha256 in html
    assert "Link text shows" in html and "www[.]paypal[.]com" in html
    assert a.email_sha256 in html


def test_safe_report_renders_without_optional_data(write_eml):
    html = render_html(analyze(write_eml(auth="mx; spf=pass; dkim=pass; dmarc=pass")))
    assert "Safe" in html and "No risk indicators" in html


def test_unknown_to_reputation_service_is_not_shown_as_clean(write_eml):
    from phishscan.enrich import EnrichmentResult

    class Unseen:
        def check_url(self, x):
            return EnrichmentResult("virustotal", x, "url", malicious=0, total=0)
        check_ip = check_hash = check_domain = check_url

    a = analyze(write_eml(auth="mx; spf=pass; dkim=pass; dmarc=pass", text="see http://evil.com/x"),
                {"virustotal": Unseen()})
    html = render_html(a)
    assert "not seen" in html and "0 flagged" not in html
