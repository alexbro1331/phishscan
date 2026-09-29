"""Generate sample emails and their reports for the README."""
from pathlib import Path

from phishscan.analyzer import analyze
from phishscan.report import render_html
from tests.helpers import build_eml

HERE = Path(__file__).parent
SAMPLES = {
    "clean": dict(auth="mx; spf=pass; dkim=pass; dmarc=pass", text="Lunch tomorrow at 1?"),
    "phishing": dict(from_="PayPal Support <support@paypa1.com>", reply_to="pay@evil-mail.ru",
                     auth="mx; spf=fail; dkim=fail; dmarc=fail", subject="Your account is suspended",
                     text="URGENT: verify your account immediately: http://bit.ly/3xYz",
                     html='<p>Dear customer, your account is <b>suspended</b>. Verify within 24 hours:</p>'
                          '<p><a href="http://secure-paypa1-login.ru/verify">https://www.paypal.com/verify</a></p>',
                     received=["from mx.google.com (mx.google.com [8.8.8.8]) by inbox.example.org "
                               "with ESMTPS; Mon, 15 Jan 2024 09:12:46 +0000",
                               "from mail.evil-mail.ru (mail.evil-mail.ru [203.0.113.50]) by mx.google.com "
                               "with ESMTP; Mon, 15 Jan 2024 09:12:44 +0000"],
                     attachments=[("invoice.pdf.exe", b"MZ fake payload")]),
}

for name, kw in SAMPLES.items():
    eml = HERE / f"{name}.eml"
    eml.write_bytes(build_eml(**kw))
    (HERE / f"{name}.report.html").write_text(render_html(analyze(eml)), encoding="utf-8")
    print("wrote", eml.name)
