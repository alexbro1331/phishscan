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


def test_link_text_mismatch():
    e = ParsedEmail(html='<a href="http://evil.com/x">https://www.paypal.com/login</a>')
    assert "link_text_mismatch" in rules(e)


def test_link_text_matching_or_plain_text_is_fine():
    ok = ParsedEmail(html='<a href="http://paypal.com/a">paypal.com</a> <a href="http://evil.com/x">click here</a>')
    assert "link_text_mismatch" not in rules(ok)


def test_punycode_domain_in_sender_or_links():
    assert "punycode_domain" in rules(ParsedEmail(from_addr="a@xn--pypal-4ve.com"))
    i = IOCs(["http://xn--pypal-4ve.com/x"], ["xn--pypal-4ve.com"], [], [])
    assert "punycode_domain" in rules(ParsedEmail(), i)


def test_rtl_override_filename_is_flagged_and_shown_safely():
    from phishscan.heuristics import visible_name
    name = "invoice\u202efdp.exe"
    e = ParsedEmail(attachments=[Attachment(name, "x", "0" * 64, 1)])
    assert "spoofed_filename" in rules(e)
    assert "\u202e" not in visible_name(name) and "U+202E" in visible_name(name)
    assert "spoofed_filename" not in rules(ParsedEmail(attachments=[Attachment("report.pdf", "x", "0" * 64, 1)]))


def test_display_name_brand_impersonation():
    def r(display, addr):
        return "display_name_brand" in rules(ParsedEmail(from_display=display, from_addr=addr))
    assert r("PayPal Support", "help@random-mail.ru")
    assert not r("PayPal", "service@paypal.com")
    assert not r("Amazon Web Services", "no-reply@aws.amazon.com")
    assert not r("Apple Music", "noreply@email.apple.com")
    assert not r("Alice Smith", "alice@example.com")
