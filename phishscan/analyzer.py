from dataclasses import dataclass

from .auth import analyze_auth
from .enrich import run_enrichment
from .extractor import extract_iocs
from .heuristics import analyze_content
from .mitre import techniques_for
from .parser import ParsedEmail, parse_eml
from .scorer import Verdict, score


@dataclass
class Analysis:
    email: ParsedEmail
    auth_results: dict
    iocs: object
    enrichment: list
    verdict: Verdict
    techniques: list
    notes: list


def analyze(path, clients=None) -> Analysis:
    email = parse_eml(path)
    auth_results, findings = analyze_auth(email)
    iocs = extract_iocs(email)
    findings += analyze_content(email, iocs)
    notes, enrichment = [], []
    if clients:
        enrichment, more = run_enrichment(iocs, clients)
        findings += more
        notes += [f"{r.source} lookup failed for {r.indicator}: {r.error}" for r in enrichment if r.error]
    else:
        notes.append("Enrichment skipped (offline mode or no API keys); verdict uses header and content analysis only.")
    verdict = score(findings)
    return Analysis(email, auth_results, iocs, enrichment, verdict, techniques_for(verdict.findings), notes)
