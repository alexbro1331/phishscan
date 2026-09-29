import hashlib

from phishscan.parser import parse_eml


def test_basic_fields(write_eml):
    p = parse_eml(write_eml(from_="Bank Support <help@bank-secure.com>", reply_to="x@evil.com",
                            subject="Urgent", auth="mx; spf=pass; dkim=pass; dmarc=pass"))
    assert p.from_addr == "help@bank-secure.com"
    assert p.from_display == "Bank Support"
    assert p.reply_to == "x@evil.com"
    assert p.subject == "Urgent"
    assert "spf=pass" in p.auth_results


def test_attachment_hash(write_eml):
    p = parse_eml(write_eml(attachments=[("inv.pdf.exe", b"abc")]))
    assert p.attachments[0].filename == "inv.pdf.exe"
    assert p.attachments[0].sha256 == hashlib.sha256(b"abc").hexdigest()
    assert p.attachments[0].size == 3


def test_html_only_has_text_fallback(write_eml):
    p = parse_eml(write_eml(text=None, html='<p>Go <a href="http://evil.com/x">here</a></p>'))
    assert "http://evil.com/x" in p.html
    assert "Go" in p.text


def test_minimal_message_does_not_crash(tmp_path):
    f = tmp_path / "m.eml"
    f.write_bytes(b"Subject: x\r\n\r\nno from, no body structure")
    p = parse_eml(f)
    assert p.from_addr == "" and p.attachments == []


def test_unnamed_attachment(tmp_path):
    raw = (b"From: a@b.com\r\nSubject: s\r\nMIME-Version: 1.0\r\n"
           b"Content-Type: multipart/mixed; boundary=B\r\n\r\n"
           b"--B\r\nContent-Type: text/plain\r\n\r\nhi\r\n"
           b"--B\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment\r\n\r\nDATA\r\n--B--\r\n")
    f = tmp_path / "u.eml"
    f.write_bytes(raw)
    a = parse_eml(f).attachments[0]
    assert a.filename == "(unnamed)" and len(a.sha256) == 64


def test_extra_fields_and_raw_headers(write_eml):
    p = parse_eml(write_eml(received=["from a (x) by b; Mon, 1 Jan 2024 10:00:00 +0000"]))
    assert p.to_addr == "bob@example.org"
    assert p.message_id == "" or p.message_id.startswith("<")
    names = [n.lower() for n, _ in p.headers]
    assert "from" in names and "received" in names


def test_received_spf_captured(tmp_path):
    f = tmp_path / "r.eml"
    f.write_bytes(b"From: a@b.com\r\nReceived-SPF: fail (domain does not designate)\r\n\r\nhi")
    assert parse_eml(f).received_spf.startswith("fail")


def test_parse_bytes_rejects_empty_and_garbage():
    import pytest
    from phishscan.parser import parse_bytes
    with pytest.raises(ValueError, match="empty"):
        parse_bytes(b"")
    with pytest.raises(ValueError, match="not a valid email"):
        parse_bytes(b"\x00\x01\x02 just binary garbage with no headers at all")


def test_parse_bytes_rejects_oversize():
    import pytest
    from phishscan.parser import parse_bytes
    with pytest.raises(ValueError, match="too large"):
        parse_bytes(b"From: a@b.com\r\n\r\n" + b"x" * 100, max_bytes=50)
