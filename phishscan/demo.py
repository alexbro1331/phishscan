"""Sample emails and demo data so the dashboard has something realistic to show."""
import random
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path

from .analyzer import analyze_bytes

SAMPLES_DIR = Path(__file__).parent / "samples"
SAMPLES = {
    "credential-phish": ("Credential phish", "A fake Microsoft password-expiry email with a forged sender, a disguised link and an HTML attachment."),
    "legit-newsletter": ("Legitimate newsletter", "A real-looking marketing email that passes authentication, to see what a clean result looks like."),
}
PASS = "mx.example.net; spf=pass; dkim=pass; dmarc=pass"
FAIL = "mx.example.net; spf=fail; dkim=fail; dmarc=fail"


def sample_bytes(name: str) -> bytes:
    if name not in SAMPLES:
        raise KeyError(name)
    return (SAMPLES_DIR / f"{name}.eml").read_bytes()


def _eml(*, from_, subject, text, to="employee@corp-example.com", reply_to=None, return_path=None,
         auth=None, html=None, attachments=(), received=None) -> bytes:
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = from_, to, subject
    for k, v in (("Reply-To", reply_to), ("Return-Path", return_path), ("Authentication-Results", auth)):
        if v:
            m[k] = v
    for r in received or []:
        m["Received"] = r
    m.set_content(text)
    if html:
        m.add_alternative(html, subtype="html")
    for name, data in attachments:
        m.add_attachment(data, maintype="application", subtype="octet-stream", filename=name)
    return m.as_bytes()


def _scenarios(rng: random.Random):
    n = lambda: rng.randint(1000, 9999)  # noqa: E731
    out = []
    for brand, domain in [("PayPal", "paypa1-secure.com"), ("Microsoft 365", "microsoft-support.co"),
                          ("Netflix", "netfIix-billing.com"), ("DHL Express", "dhl-parcel-track.ru"),
                          ("Apple ID", "apple-verify.net"), ("Amazon", "amazon-orders.info")]:
        word = brand.split()[0].lower()
        out.append(("Malicious", dict(
            from_=f"{brand} Support <no-reply@{domain}>", reply_to=f"help@mail-{n()}.ru", auth=FAIL,
            subject=f"Action required: verify your {brand} account (ref {n()})",
            text=f"URGENT: your account will be suspended within 24 hours. Verify immediately: http://bit.ly/{n()}",
            html=f'<p>Verify now:</p><a href="http://secure-login-{n()}.ru/verify">https://www.{word}.com/verify</a>',
            received=[f"from relay.mailer-{n()}.ru (relay.mailer-{n()}.ru [185.220.101.{rng.randint(2, 250)}]) "
                      f"by mx.example.net; Mon, 15 Jan 2024 09:12:44 +0000"],
            attachments=[(f"Invoice_{n()}.pdf.exe", b"MZ")] if rng.random() < .5 else [])))
    out.append(("Malicious", dict(
        from_="Payroll Team <payroll@corp-example-hr.com>", reply_to="payroll-update@outlook-verify.ru", auth=FAIL,
        subject=f"Updated payroll details - action required ({n()})",
        text="Please review your updated payroll statement immediately.",
        html=f'<a href="http://xn--corp-exmple-hr-9ub.com/login">https://hr.corp-example.com/payroll</a>',
        attachments=[("Payroll\u202efdp.exe", b"MZ")])))
    for _ in range(4):
        out.append(("Suspicious", dict(
            from_=f"HR Payroll <hr@company-payroll-{n()}.net>", reply_to=f"hr-desk@gmail-{n()}.com",
            auth="mx.example.net; spf=fail; dkim=pass; dmarc=pass", subject=f"Benefits enrollment reminder #{n()}",
            text="Please confirm your benefits selection this week.")))
    for _ in range(3):
        out.append(("Suspicious", dict(
            from_=f"Amazon Delivery <ship@parcel-hub-{n()}.io>", subject=f"Your package is delayed ({n()})",
            text=f"Track it here: https://bit.ly/{n()}")))
    for _ in range(2):
        out.append(("Suspicious", dict(
            from_=f"IT Helpdesk <helpdesk@corp-it-{n()}.co>", reply_to=f"it-support@proton-{n()}.me",
            auth="mx.example.net; spf=pass; dkim=pass; dmarc=fail", subject=f"Mailbox storage almost full ({n()})",
            text="Your mailbox is 98% full. Upgrade your quota.")))
    for sender, subj in [("Acme Weekly <news@acme-corp.com>", "Your weekly digest"),
                         ("GitHub <notifications@github.com>", "[repo] Pull request #{} merged"),
                         ("Google Calendar <calendar-notification@google.com>", "Invitation: Sprint review @ Tue"),
                         ("Stripe <receipts@stripe.com>", "Your receipt from Vercel Inc. #{}"),
                         ("Slack <feedback@slack.com>", "New messages in #general"),
                         ("Priya Nair <priya.nair@corp-example.com>", "Notes from today's standup"),
                         ("LinkedIn <messages-noreply@linkedin.com>", "You have 3 new messages"),
                         ("Zoom <no-reply@zoom.us>", "Cloud recording is now available")]:
        for _ in range(rng.randint(1, 2)):
            out.append(("Safe", dict(from_=sender, auth=PASS, subject=subj.format(n()) + f" ({n()})",
                                     text="Hello, this is a routine message.")))
    return out


def seed_demo(store, days: int = 14, now=None) -> int:
    """Fill an empty store with realistic cases spread over the last `days` days. Returns how many were added."""
    if store.stats(days=1)["total"] > 0:
        return 0
    rng = random.Random(7)
    now = now or datetime.now(timezone.utc)
    added = 0
    for label, kw in _scenarios(rng):
        a = analyze_bytes(_eml(**kw))
        ts = now - timedelta(minutes=int(rng.triangular(5, days * 1440 - 5, 5)))
        cid, dup = store.add(a, created_at=ts.strftime("%Y-%m-%dT%H:%M:%SZ"))
        if dup:
            continue
        added += 1
        if label == "Malicious":
            store.update(cid, status=rng.choice(["resolved", "resolved", "investigating", "new"]))
        elif label == "Suspicious":
            store.update(cid, status=rng.choice(["investigating", "new", "false_positive"]))
        else:
            store.update(cid, status=rng.choice(["resolved", "resolved", "new"]))
    return added
