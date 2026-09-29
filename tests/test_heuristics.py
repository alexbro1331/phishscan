from phishscan.extractor import IOCs
from phishscan.heuristics import analyze_content
from phishscan.parser import Attachment, ParsedEmail


def rules(email, iocs=None):
    return {f.rule for f in analyze_content(email, iocs or IOCs([], [], [], []))}


def test_shortener_and_ip_literal():
    i = IOCs(["https://bit.ly/x", "http://8.8.8.8/a"], ["bit.ly"], ["8.8.8.8"], [])
    assert rules(ParsedEmail(), i) == {"url_shortener", "ip_literal_url"}


def test_urgency_needs_two_phrases():
    assert "urgency_language" in rules(ParsedEmail(text="URGENT: verify your account immediately"))
    assert "urgency_language" not in rules(ParsedEmail(text="Please act now"))


def test_dangerous_extension_double_ext():
    e = ParsedEmail(attachments=[Attachment("invoice.pdf.exe", "x", "0" * 64, 1)])
    assert rules(e) == {"dangerous_extension"}


def test_lookalike_domains():
    for addr, expected in [("a@paypa1.com", True), ("a@paypal-secure.com", True), ("a@paypal.com", False),
                           ("a@example.com", False), ("a@maple.com", False)]:
        assert ("lookalike_domain" in rules(ParsedEmail(from_addr=addr))) is expected, addr
