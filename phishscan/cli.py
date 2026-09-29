import argparse
import os
import sys
from pathlib import Path

from .analyzer import analyze
from .extractor import defang
from .report import render_html, render_json

EXIT = {"Safe": 0, "Suspicious": 1, "Malicious": 2}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="phishscan", description="Analyze a suspicious .eml file")
    p.add_argument("eml")
    p.add_argument("-o", "--output", help="HTML report path (default: <eml>.report.html)")
    p.add_argument("--json", action="store_true", help="also write a JSON report")
    p.add_argument("--offline", action="store_true", help="skip API lookups")
    args = p.parse_args(argv)

    eml = Path(args.eml)
    if not eml.is_file():
        print(f"error: file not found: {eml}", file=sys.stderr)
        return 3

    clients = None
    if not args.offline:
        try:
            from dotenv import load_dotenv
            load_dotenv()
        except ImportError:
            pass
        from .enrich import build_clients
        from .enrich.cache import Cache
        cache_dir = Path.home() / ".phishscan"
        cache_dir.mkdir(exist_ok=True)
        clients = build_clients(os.environ, Cache(str(cache_dir / "cache.sqlite")))

    a = analyze(eml, clients)
    out = Path(args.output) if args.output else eml.with_suffix(".report.html")
    out.write_text(render_html(a), encoding="utf-8")
    if args.json:
        out.with_suffix(".json").write_text(render_json(a), encoding="utf-8")

    print(f"Verdict: {a.verdict.label} (score {a.verdict.score}/100)")
    for f in a.verdict.findings:
        print(f"  +{f.points:<3} {f.reason}")
    for u in a.iocs.urls:
        print(f"  IOC: {defang(u)}")
    for n in a.notes:
        print(f"  note: {n}")
    print(f"Report: {out}")
    return EXIT[a.verdict.label]
