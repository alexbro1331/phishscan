import hashlib
import re
from dataclasses import dataclass, field
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path


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
    reply_to: str = ""
    return_path: str = ""
    auth_results: str = ""
    received: list = field(default_factory=list)
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


def parse_eml(path) -> ParsedEmail:
    msg = BytesParser(policy=policy.default).parsebytes(Path(path).read_bytes())
    display, addr = _addr(msg.get("From"))
    e = ParsedEmail(
        subject=str(msg.get("Subject", "") or ""),
        from_display=display,
        from_addr=addr,
        reply_to=_addr(msg.get("Reply-To"))[1],
        return_path=_addr(msg.get("Return-Path"))[1],
        auth_results=" ".join(str(v) for v in msg.get_all("Authentication-Results", [])),
        received=[str(v) for v in msg.get_all("Received", [])],
    )
    for part in msg.walk():
        if part.is_multipart():
            continue
        is_att = part.get_content_disposition() == "attachment" or part.get_filename()
        if is_att:
            data = part.get_payload(decode=True) or b""
            e.attachments.append(Attachment(part.get_filename() or "(unnamed)", part.get_content_type(),
                                            hashlib.sha256(data).hexdigest(), len(data)))
        elif part.get_content_type() == "text/plain" and not e.text:
            e.text = _body(part)
        elif part.get_content_type() == "text/html" and not e.html:
            e.html = _body(part)
    if not e.text and e.html:
        e.text = _strip_tags(e.html)
    return e
