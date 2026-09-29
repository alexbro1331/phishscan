import argparse
import csv
import logging
import os
import sys
from pathlib import Path

from . import __version__
from .analyzer import analyze
from .extractor import defang
from .report import render_html, render_json, render_page

EXIT = {"Safe": 0, "Suspicious": 1, "Malicious": 2}
EXIT_BAD_INPUT = 3


def _build_clients(offline: bool):
    if offline:
        return None
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass
    from .enrich import build_clients
    from .enrich.cache import Cache
    cache_dir = Path.home() / ".phishscan"
    cache_dir.mkdir(exist_ok=True)
    return build_clients(os.environ, Cache(str(cache_dir / "cache.sqlite")))


def _single(eml: Path, args, clients) -> int:
    try:
        a = analyze(eml, clients)
    except ValueError as exc:
        print(f"error: {eml.name}: {exc}", file=sys.stderr)
        return EXIT_BAD_INPUT
    out = Path(args.output) if args.output else eml.with_suffix(".report.html")
    out.parent.mkdir(parents=True, exist_ok=True)
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


def _batch(folder: Path, args, clients) -> int:
    emls = sorted(p for p in folder.iterdir() if p.is_file() and p.suffix.lower() == ".eml")
    if not emls:
        print(f"error: no .eml files found in {folder}", file=sys.stderr)
        return EXIT_BAD_INPUT
    out = Path(args.output) if args.output else folder / "phishscan-reports"
    out.mkdir(parents=True, exist_ok=True)
    rows, worst = [], 0
    for eml in emls:
        try:
            a = analyze(eml, clients)
        except ValueError as exc:
            rows.append({"file": eml.name, "verdict": "Error", "score": "", "from": "", "subject": "",
                         "findings": str(exc), "sha256": "", "report": ""})
            continue
        report = f"{eml.stem}.report.html"
        (out / report).write_text(render_html(a), encoding="utf-8")
        if args.json:
            (out / f"{eml.stem}.report.json").write_text(render_json(a), encoding="utf-8")
        worst = max(worst, EXIT[a.verdict.label])
        rows.append({"file": eml.name, "verdict": a.verdict.label, "score": a.verdict.score,
                     "from": a.email.from_addr, "subject": a.email.subject,
                     "findings": "; ".join(f.rule for f in a.verdict.findings),
                     "sha256": a.email_sha256, "report": report})
    with (out / "summary.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["file", "verdict", "score", "from", "subject", "findings",
                                           "sha256", "report"])
        w.writeheader()
        w.writerows(rows)
    counts = {k: sum(1 for r in rows if r["verdict"] == k) for k in ("Malicious", "Suspicious", "Safe", "Error")}
    (out / "index.html").write_text(render_page("batch.html",
                                                    rows=sorted(rows, key=lambda r: -(r["score"] if r["score"] != "" else -1)), counts=counts, total=len(rows)),
                                    encoding="utf-8")
    print(f"Analyzed {len(rows)} emails: {counts['Malicious']} malicious, {counts['Suspicious']} suspicious, "
          f"{counts['Safe']} safe, {counts['Error']} unreadable")
    print(f"Summary: {out / 'index.html'}")
    return worst


def _serve(argv) -> int:
    p = argparse.ArgumentParser(prog="phishscan serve", description="Run the PhishScan web app")
    p.add_argument("--host", default=os.environ.get("PHISHSCAN_HOST", "127.0.0.1"))
    p.add_argument("--port", type=int, default=int(os.environ.get("PORT") or os.environ.get("PHISHSCAN_PORT") or 8000))
    p.add_argument("--threads", type=int, default=4)
    p.add_argument("--demo", action="store_true", help="start with sample data in memory (nothing is saved)")
    args = p.parse_args(argv)
    from . import web
    web.serve(host=args.host, port=args.port, threads=args.threads, demo=args.demo)
    return 0


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv and argv[0] == "serve":
        return _serve(argv[1:])
    p = argparse.ArgumentParser(
        prog="phishscan",
        description="Analyze a suspicious .eml file (or a folder of them). "
                    "Use 'phishscan serve' to run the web app.",
        epilog="Exit codes: 0 Safe, 1 Suspicious, 2 Malicious, 3 bad input.")
    p.add_argument("target", help="an .eml file or a folder containing .eml files")
    p.add_argument("-o", "--output", help="HTML report path (file mode) or output folder (folder mode)")
    p.add_argument("--json", action="store_true", help="also write JSON report(s)")
    p.add_argument("--offline", action="store_true", help="skip API lookups")
    p.add_argument("-v", "--verbose", action="store_true", help="show debug logging")
    p.add_argument("--version", action="version", version=f"phishscan {__version__}")
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING)

    target = Path(args.target)
    if not target.exists():
        print(f"error: file not found: {target}", file=sys.stderr)
        return EXIT_BAD_INPUT
    clients = _build_clients(args.offline)
    return _batch(target, args, clients) if target.is_dir() else _single(target, args, clients)
