import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .extractor import defang

_ENV = Environment(loader=FileSystemLoader(Path(__file__).parent / "templates"),
                   autoescape=select_autoescape(["html", "j2"]))
_ENV.filters["defang"] = defang

ACTIONS = {
    "Safe": ["No strong phishing indicators found. Still avoid entering credentials via email links."],
    "Suspicious": ["Do not click links or open attachments until verified.",
                   "Confirm with the sender through a separate channel.",
                   "Report to the security team for manual review."],
    "Malicious": ["Do NOT click links or open attachments.", "Quarantine/delete the message for all recipients.",
                  "Block the sender domain and listed IOCs at the mail gateway and proxy.",
                  "If anyone interacted with it, reset credentials and start incident response."],
}


def render_html(a) -> str:
    return _ENV.get_template("report.html.j2").render(a=a, actions=ACTIONS[a.verdict.label])


def render_json(a) -> str:
    data = {
        "subject": a.email.subject, "from": a.email.from_addr,
        "auth_results": a.auth_results,
        "verdict": {"score": a.verdict.score, "label": a.verdict.label,
                    "findings": [vars(f) for f in a.verdict.findings]},
        "iocs": {"urls": [defang(u) for u in a.iocs.urls], "domains": [defang(d) for d in a.iocs.domains],
                 "ips": [defang(i) for i in a.iocs.ips],
                 "hashes": [{"file": n, "sha256": h} for n, h in a.iocs.hashes]},
        "enrichment": [vars(r) for r in a.enrichment],
        "mitre": [{"id": i, "name": n} for i, n in a.techniques],
        "notes": a.notes,
    }
    return json.dumps(data, indent=2)
