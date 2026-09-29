import re

from .parser import ParsedEmail
from .weights import finding

_RES = re.compile(r"\b(spf|dkim|dmarc)=(\w+)", re.I)
_BAD = {"fail", "softfail", "permerror"}
_SPF_HDR = re.compile(r"\s*(pass|fail|softfail|neutral|none|permerror|temperror)\b", re.I)
_EMAIL_IN_TEXT = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")


def domain_of(addr: str) -> str:
    return addr.rsplit("@", 1)[1].lower() if "@" in addr else ""


def aligned(a: str, b: str) -> bool:
    """Same domain, or one is a subdomain of the other (mail.example.com vs example.com)."""
    a, b = a.lower(), b.lower()
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def analyze_auth(email: ParsedEmail):
    results: dict[str, str] = {}
    for mech, res in _RES.findall(email.auth_results or ""):
        results.setdefault(mech.lower(), res.lower())
    if "spf" not in results:
        m = _SPF_HDR.match(email.received_spf or "")
        if m:
            results["spf"] = m.group(1).lower()
    findings = []
    if not results:
        findings.append(finding("no_auth_results",
                                "No Authentication-Results header; SPF/DKIM/DMARC cannot be verified"))
    for mech in ("spf", "dkim", "dmarc"):
        if results.get(mech) in _BAD:
            findings.append(finding(f"{mech}_fail", f"{mech.upper()} result: {results[mech]}"))
    sender = domain_of(email.from_addr)
    if email.reply_to and sender and not aligned(domain_of(email.reply_to), sender):
        findings.append(finding("reply_to_mismatch",
                                f"Reply-To domain ({domain_of(email.reply_to)}) differs from From domain ({sender})"))
    if email.return_path and sender and not aligned(domain_of(email.return_path), sender):
        findings.append(finding("return_path_mismatch",
                                f"Return-Path domain ({domain_of(email.return_path)}) differs from From domain ({sender})"))
    m = _EMAIL_IN_TEXT.search(email.from_display or "")
    if m and sender and m.group(1).lower() != sender:
        findings.append(finding("display_name_spoof",
                                f"Display name shows an address at {m.group(1).lower()} but the real sender is {sender}"))
    return results, findings
