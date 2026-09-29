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
                     attachments=[("invoice.pdf.exe", b"MZ fake payload")]),
}

for name, kw in SAMPLES.items():
    eml = HERE / f"{name}.eml"
    eml.write_bytes(build_eml(**kw))
    (HERE / f"{name}.report.html").write_text(render_html(analyze(eml)), encoding="utf-8")
    print("wrote", eml.name)
