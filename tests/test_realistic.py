from pathlib import Path

from phishscan.analyzer import analyze

FIX = Path(__file__).parent / "fixtures"


def test_realistic_credential_phish_is_malicious_with_expected_evidence():
    a = analyze(FIX / "realistic_phish.eml")
    rules = {f.rule for f in a.verdict.findings}
    assert a.verdict.label == "Malicious"
    assert {"dkim_fail", "spf_fail", "dmarc_fail", "reply_to_mismatch", "return_path_mismatch",
            "lookalike_domain", "link_text_mismatch", "dangerous_extension", "urgency_language"} <= rules
    assert a.email.from_display == "Microsoft Account Team"           # RFC 2047 header decoded
    assert a.email.subject.startswith("Action required:")
    assert "185.220.101.45" in a.iocs.ips                              # sender IP from Received chain
    assert a.email.attachments[0].filename == "Payroll_Q1.html"
    assert "being suspended" in a.email.text                           # quoted-printable soft line break joined


def test_legitimate_newsletter_is_not_flagged():
    a = analyze(FIX / "legit_newsletter.eml")
    assert a.verdict.label == "Safe", [(f.rule, f.reason) for f in a.verdict.findings]
    assert a.verdict.score == 0


def test_truncated_and_corrupted_emails_never_crash():
    import random

    from phishscan.analyzer import analyze_bytes
    from phishscan.report import render_html, render_json

    raw = (FIX / "realistic_phish.eml").read_bytes()
    rng = random.Random(1234)
    samples = [raw[:n] for n in range(1, len(raw), 37)]
    for _ in range(150):
        b = bytearray(raw)
        for _ in range(rng.randint(1, 12)):
            b[rng.randrange(len(b))] = rng.randrange(256)
        samples.append(bytes(b))
    analyzed = 0
    for data in samples:
        try:
            a = analyze_bytes(data)
        except ValueError:
            continue  # rejected cleanly with a readable message
        render_html(a)
        render_json(a)
        analyzed += 1
    assert analyzed > 100
