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
