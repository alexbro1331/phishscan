import re
from html.parser import HTMLParser
from urllib.parse import urlparse

from .auth import domain_of
from .extractor import defang
from .weights import finding

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly"}
DANGEROUS_EXT = {".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".iso", ".img", ".lnk",
                 ".docm", ".xlsm", ".jar", ".html", ".htm"}
BRANDS = ["paypal", "microsoft", "google", "amazon", "apple", "netflix", "facebook", "fedex",
          "linkedin", "instagram"]
URGENCY = re.compile(r"urgent|immediately|verify your account|suspended|within 24 hours|"
                     r"password (?:will )?expires?|act now", re.I)
_BIDI = {chr(c) for c in (*range(0x202A, 0x202F), *range(0x2066, 0x206A), 0x200E, 0x200F)}
_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_TEXT_DOMAIN = re.compile(r"^(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/:?#]|$)", re.I)


class _Links(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.pairs, self._href, self._text = [], None, []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href, self._text = dict(attrs).get("href"), []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.pairs.append((self._href, "".join(self._text).strip()))
            self._href = None


def _base(host: str) -> str:
    return ".".join(host.lower().split(".")[-2:])


def _link_mismatches(html: str):
    if not html:
        return []
    parser = _Links()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        return []
    out = []
    for href, text in parser.pairs:
        m = _TEXT_DOMAIN.match(text)
        host = (urlparse(href).hostname or "") if href.lower().startswith(("http://", "https://")) else ""
        if m and host and _base(m.group(1)) != _base(host):
            out.append((m.group(1), host))
    return out


def visible_name(filename: str) -> str:
    """Make invisible direction-override characters visible so a filename cannot lie in a report."""
    return "".join(f"<U+{ord(c):04X}>" if c in _BIDI else c for c in filename)


def dangerous_ext(filename: str) -> str | None:
    name = filename.lower()
    ext = name[name.rfind("."):] if "." in name else ""
    return ext if ext in DANGEROUS_EXT else None


def _lev(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _lookalike(domain: str):
    parts = domain.split(".")
    if len(parts) < 2:
        return None
    label = parts[-2]
    if label in BRANDS:
        return None
    for brand in BRANDS:
        if (len(brand) >= 5 and brand in label) or (len(label) >= 6 and _lev(label, brand) <= 1):
            return brand
    return None


def analyze_content(email, iocs):
    out = []
    for u in iocs.urls:
        host = (urlparse(u).hostname or "").lower()
        if host in SHORTENERS:
            out.append(finding("url_shortener", f"URL shortener used ({host}) hides the real destination"))
        elif _IPV4.match(host):
            out.append(finding("ip_literal_url", f"Link points to a raw IP address ({host})"))
    if len(URGENCY.findall(f"{email.subject} {email.text}")) >= 2:
        out.append(finding("urgency_language", "Multiple urgency/pressure phrases in subject or body"))
    for a in email.attachments:
        if any(c in _BIDI for c in a.filename):
            out.append(finding("spoofed_filename",
                               f"Attachment name contains a hidden direction-override character: {visible_name(a.filename)}"))
        ext = dangerous_ext(a.filename)
        if ext:
            out.append(finding("dangerous_extension", f"Attachment '{visible_name(a.filename)}' has a risky file type ({ext})"))
    for shown, real in _link_mismatches(email.html):
        out.append(finding("link_text_mismatch",
                           f"Link text shows {defang(shown)} but points to {defang(real)}"))
    puny = [d for d in [*iocs.domains, domain_of(email.from_addr)]
            if any(label.startswith("xn--") for label in d.split("."))]
    if puny:
        out.append(finding("punycode_domain",
                           f"Internationalized (punycode) domain can hide a look-alike: {defang(puny[0])}"))
    sender_parts = domain_of(email.from_addr).split(".")
    sender_label = sender_parts[-2] if len(sender_parts) >= 2 else ""
    shown = email.from_display.lower()
    for b in BRANDS:
        if re.search(rf"\b{b}\b", shown) and b not in sender_label:
            out.append(finding("display_name_brand",
                               f"Display name mentions '{b}' but the message was sent from {defang(domain_of(email.from_addr))}"))
            break
    brand = _lookalike(domain_of(email.from_addr))
    if brand:
        out.append(finding("lookalike_domain",
                           f"Sender domain '{domain_of(email.from_addr)}' imitates the brand '{brand}'"))
    return out
