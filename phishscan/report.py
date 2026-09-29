import ipaddress
import json
import math
import re
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from . import __version__
from .extractor import defang
from .heuristics import dangerous_ext, visible_name
from .mitre import TECHNIQUES

_ENV = Environment(loader=FileSystemLoader(Path(__file__).parent / "templates"),
                   autoescape=select_autoescape(["html", "j2"]))
_ENV.filters["defang"] = defang

ACTIONS = {
    "Safe": ["No strong phishing indicators found. Still avoid entering credentials via email links.",
             "If something still feels off, confirm with the sender through a separate channel."],
    "Suspicious": ["Do not click links or open attachments until the message is verified.",
                   "Confirm with the sender through a separate channel (phone or a new message).",
                   "Report the message to your security team for manual review."],
    "Malicious": ["Do NOT click links or open attachments.",
                  "Quarantine or delete the message for all recipients.",
                  "Block the sender domain and the listed indicators at the mail gateway and proxy.",
                  "If anyone interacted with it, reset their credentials and start incident response."],
}
HEADLINES = {
    "Safe": "No significant phishing indicators found",
    "Suspicious": "This message shows signs of phishing",
    "Malicious": "This message is very likely phishing or spoofing",
}
SUMMARIES = {
    "Safe": "Authentication and content checks found nothing alarming. Normal caution still applies.",
    "Suspicious": "Several indicators do not add up. Verify it independently before interacting with it.",
    "Malicious": "Multiple strong indicators were detected. Do not interact with it and escalate to your security team.",
}
_RADIUS = 58
_CIRC = 2 * math.pi * _RADIUS
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _sev(points: int) -> str:
    return "high" if points >= 25 else "medium" if points >= 15 else "low"


def _human_size(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{int(size)} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"


def _public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _hops(received: list) -> list:
    """Oldest hop first. Best-effort parse of Received headers."""
    hops = []
    for raw in reversed(received or []):
        frm = re.search(r"\bfrom\s+(\S+)", raw, re.I)
        by = re.search(r"\bby\s+(\S+)", raw, re.I)
        ips = _IP.findall(raw)
        ip = next((i for i in ips if _public(i)), ips[0] if ips else "")
        time = raw.rsplit(";", 1)[1].strip() if ";" in raw else ""
        hops.append({"frm": defang(frm.group(1)) if frm else "", "by": defang(by.group(1)) if by else "",
                     "ip": defang(ip) if ip else "", "time": time})
    return hops


def _chip(source, *, malicious=0, total=0, score=None, error=None):
    if error:
        return {"cls": "warn", "text": f"{source}: lookup failed"}
    if score is not None:
        return {"cls": "bad" if score >= 50 else "ok" if score == 0 else "warn", "text": f"{source}: abuse {score}%"}
    if total == 0 and malicious == 0:
        return {"cls": "", "text": f"{source}: not seen"}
    cls = "bad" if malicious >= 3 else "warn" if malicious else "ok"
    return {"cls": cls, "text": f"{source}: {malicious}/{total}" if total else f"{source}: {malicious} flagged"}


def build_context(a) -> dict:
    v, e = a.verdict, a.email
    rep: dict[str, list] = {}
    for r in a.enrichment:
        rep.setdefault(r.indicator, []).append(
            _chip(r.source, malicious=r.malicious, total=r.total, score=r.score, error=r.error))
    iocs = [{"type": "URL", "value": defang(u), "chips": rep.get(u, [])} for u in a.iocs.urls]
    iocs += [{"type": "Domain", "value": defang(d), "chips": rep.get(d, [])} for d in a.iocs.domains]
    iocs += [{"type": "IP", "value": defang(i), "chips": rep.get(i, [])} for i in a.iocs.ips]
    auth = []
    for mech in ("spf", "dkim", "dmarc"):
        res = a.auth_results.get(mech)
        cls = "warn" if res is None else "ok" if res == "pass" else "bad" if res in ("fail", "softfail", "permerror") else "warn"
        auth.append({"name": mech.upper(), "result": (res or "not present").upper(), "cls": cls})
    attachments = []
    for att in e.attachments:
        chips = [{"cls": "bad", "text": f"risky type {dangerous_ext(att.filename)}"}] if dangerous_ext(att.filename) else []
        chips += rep.get(att.sha256, [])
        attachments.append({"filename": visible_name(att.filename), "content_type": att.content_type,
                            "size": _human_size(att.size), "sha256": att.sha256,
                            "chips": chips or [{"cls": "ok", "text": "no issues found"}]})
    return {
        "label": v.label, "score": v.score, "radius": _RADIUS, "circ": f"{_CIRC:.1f}",
        "dash": f"{_CIRC * v.score / 100:.1f}",
        "headline": HEADLINES[v.label], "summary": SUMMARIES[v.label],
        "subject": e.subject, "from_display": e.from_display, "from_addr": e.from_addr,
        "to_addr": e.to_addr, "date": e.date, "message_id": e.message_id,
        "notes": a.notes,
        "findings": [{"rule": f.rule.replace("_", " "), "points": f.points, "reason": f.reason,
                      "sev": _sev(f.points), "mitre": f.mitre, "mitre_name": TECHNIQUES.get(f.mitre, "")}
                     for f in v.findings],
        "auth": auth, "hops": _hops(e.received), "attachments": attachments, "iocs": iocs,
        "techniques": [{"id": i, "name": n} for i, n in a.techniques],
        "actions": ACTIONS[v.label], "headers": e.headers,
        "analyzed_at": a.analyzed_at, "email_sha256": a.email_sha256,
    }


def render_page(template: str, **ctx) -> str:
    ctx.setdefault("version", __version__)
    return _ENV.get_template(template).render(**ctx)


def render_html(a) -> str:
    return render_page("report.html.j2", r=build_context(a), version=a.version)


def render_json(a) -> str:
    ctx = build_context(a)
    data = {
        "tool": {"name": "phishscan", "version": a.version}, "analyzed_at": a.analyzed_at,
        "email_sha256": a.email_sha256,
        "subject": a.email.subject, "from": a.email.from_addr, "to": a.email.to_addr, "date": a.email.date,
        "auth_results": a.auth_results,
        "verdict": {"score": a.verdict.score, "label": a.verdict.label,
                    "findings": [vars(f) for f in a.verdict.findings]},
        "iocs": {"urls": [defang(u) for u in a.iocs.urls], "domains": [defang(d) for d in a.iocs.domains],
                 "ips": [defang(i) for i in a.iocs.ips],
                 "hashes": [{"file": n, "sha256": h} for n, h in a.iocs.hashes]},
        "mail_route": ctx["hops"],
        "enrichment": [vars(r) for r in a.enrichment],
        "mitre": [{"id": i, "name": n} for i, n in a.techniques],
        "notes": a.notes,
    }
    return json.dumps(data, indent=2)
