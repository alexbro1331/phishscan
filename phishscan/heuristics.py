import re
from urllib.parse import urlparse

from .auth import domain_of
from .weights import finding

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly"}
DANGEROUS_EXT = {".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".iso", ".img", ".lnk",
                 ".docm", ".xlsm", ".jar", ".html", ".htm"}
BRANDS = ["paypal", "microsoft", "google", "amazon", "apple", "netflix", "facebook", "fedex",
          "linkedin", "instagram"]
URGENCY = re.compile(r"urgent|immediately|verify your account|suspended|within 24 hours|"
                     r"password (?:will )?expires?|act now", re.I)
_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


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
        name = a.filename.lower()
        ext = name[name.rfind("."):] if "." in name else ""
        if ext in DANGEROUS_EXT:
            out.append(finding("dangerous_extension", f"Attachment '{a.filename}' has a risky file type ({ext})"))
    brand = _lookalike(domain_of(email.from_addr))
    if brand:
        out.append(finding("lookalike_domain",
                           f"Sender domain '{domain_of(email.from_addr)}' imitates the brand '{brand}'"))
    return out
