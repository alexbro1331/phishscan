import hashlib
import re
from dataclasses import dataclass, field
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path

MAX_EMAIL_BYTES = 25 * 1024 * 1024


@dataclass
class Attachment:
    filename: str
    content_type: str
    sha256: str
    size: int


@dataclass
class ParsedEmail:
    subject: str = ""
    from_display: str = ""
    from_addr: str = ""
    to_addr: str = ""
    reply_to: str = ""
    return_path: str = ""
    date: str = ""
    message_id: str = ""
    auth_results: str = ""
    received_spf: str = ""
    received: list = field(default_factory=list)
    headers: list = field(default_factory=list)
    text: str = ""
    html: str = ""
    attachments: list = field(default_factory=list)


def _addr(value) -> tuple[str, str]:
    display, addr = parseaddr(str(value or ""))
    return display, addr.lower()


def _body(part) -> str:
    try:
        return part.get_content()
    except Exception:
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="replace")


def _strip_tags(html: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html)).strip()


def _clean(value) -> str:
    return " ".join(str(value or "").split())


def parse_bytes(data: bytes, max_bytes: int = MAX_EMAIL_BYTES) -> ParsedEmail:
    if not data or not data.strip():
        raise ValueError("The file is empty.")
    if len(data) > max_bytes:
        raise ValueError(f"The email is too large (limit {max_bytes // (1024 * 1024) or 1} MB).")
    msg = BytesParser(policy=policy.default).parsebytes(data)
    if not msg.keys():
        raise ValueError("This does not look like an email (not a valid email: no headers found). "
                         "Export the message as .eml and try again.")
    display, addr = _addr(msg.get("From"))
    e = ParsedEmail(
        subject=_clean(msg.get("Subject", "")),
        from_display=display,
        from_addr=addr,
        to_addr=_addr(msg.get("To"))[1],
        reply_to=_addr(msg.get("Reply-To"))[1],
        return_path=_addr(msg.get("Return-Path"))[1],
        date=_clean(msg.get("Date", "")),
        message_id=_clean(msg.get("Message-ID", "")),
        auth_results=" ".join(_clean(v) for v in msg.get_all("Authentication-Results", [])),
        received_spf=" ".join(_clean(v) for v in msg.get_all("Received-SPF", [])),
        received=[_clean(v) for v in msg.get_all("Received", [])],
        headers=[(k, _clean(v)) for k, v in msg.raw_items()],
    )
    for part in msg.walk():
        if part.is_multipart():
            continue
        is_att = part.get_content_disposition() == "attachment" or part.get_filename()
        if is_att:
            payload = part.get_payload(decode=True) or b""
            e.attachments.append(Attachment(part.get_filename() or "(unnamed)", part.get_content_type(),
                                            hashlib.sha256(payload).hexdigest(), len(payload)))
        elif part.get_content_type() == "text/plain" and not e.text:
            e.text = _body(part)
        elif part.get_content_type() == "text/html" and not e.html:
            e.html = _body(part)
    if not e.text and e.html:
        e.text = _strip_tags(e.html)
    return e


def parse_eml(path, max_bytes: int = MAX_EMAIL_BYTES) -> ParsedEmail:
    return parse_bytes(Path(path).read_bytes(), max_bytes)
