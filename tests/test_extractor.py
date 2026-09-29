from phishscan.extractor import defang, extract_iocs
from phishscan.parser import Attachment, ParsedEmail


def test_extract_iocs():
    e = ParsedEmail(
        text="Go http://evil.com/login?a=1. and https://bit.ly/x and again http://evil.com/login?a=1",
        received=["from mail ([8.8.8.8]) by mx", "from lan ([10.0.0.1]) by mx"],
        attachments=[Attachment("a.exe", "application/octet-stream", "ab" * 32, 3)])
    i = extract_iocs(e)
    assert i.urls == ["http://evil.com/login?a=1", "https://bit.ly/x"]
    assert i.domains == ["evil.com", "bit.ly"]
    assert i.ips == ["8.8.8.8"]
    assert i.hashes == [("a.exe", "ab" * 32)]


def test_urls_from_html_only():
    e = ParsedEmail(html='<a href="http://evil.com/x">click</a>')
    assert extract_iocs(e).urls == ["http://evil.com/x"]


def test_ip_literal_url_counts_as_ip_not_domain():
    i = extract_iocs(ParsedEmail(text="http://8.8.4.4/x"))
    assert i.ips == ["8.8.4.4"] and i.domains == []


def test_defang():
    assert defang("http://evil.com/a") == "hxxp://evil[.]com/a"
    assert defang("8.8.8.8") == "8[.]8[.]8[.]8"
