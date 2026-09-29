"""PhishScan web console: dashboard, case management, indicators, settings and a small JSON API.

Security model: optional password login (PHISHSCAN_PASSWORD), CSRF tokens on every state-changing form/fetch,
strict Content-Security-Policy (scripts only from this server), per-client rate limits and an upload cap.
Emails are analyzed in memory; only the analysis result (never the message body) is saved.
"""
import csv
import hmac
import io
import json
import logging
import math
import os
import secrets
import threading
import time
from collections import defaultdict, deque
from pathlib import Path

from jinja2 import FileSystemLoader
from flask import Flask, Response, jsonify, redirect, render_template, request, session, url_for
from werkzeug.exceptions import HTTPException

from . import __version__
from .analyzer import analyze_bytes
from .demo import SAMPLES, sample_bytes, seed_demo
from .extractor import defang
from .labels import rule_title
from .mitre import RULE_TO_TECHNIQUE
from .report import render_json, render_report_html
from .store import STATUSES, VERDICTS, Store
from .viz import activity_chart, donut, sparkline
from .weights import WEIGHTS

log = logging.getLogger("phishscan.web")

CSP = ("default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
       "connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
REPORT_CSP = ("default-src 'none'; style-src 'unsafe-inline'; img-src data:; script-src 'none'; "
              "base-uri 'none'; frame-ancestors 'none'")
STATUS_LABELS = {"new": "New", "investigating": "Investigating", "resolved": "Resolved", "false_positive": "False positive"}
PER_PAGE = 20
IOC_PER_PAGE = 50
_UNSET = object()
_PUBLIC = {"login", "healthz", "static"}


class RateLimit:
    """Sliding-window per-client limiter (per minute). In-memory, per process."""

    def __init__(self, per_minute: int, clock=time.monotonic):
        self.per_minute, self.clock = per_minute, clock
        self.hits = defaultdict(deque)
        self.last_sweep = clock()
        self.lock = threading.Lock()

    def allow(self, key: str) -> bool:
        with self.lock:
            now = self.clock()
            if now - self.last_sweep >= 60:  # drop idle clients so the table cannot grow forever
                for k in [k for k, d in self.hits.items() if not d or now - d[-1] >= 60]:
                    del self.hits[k]
                self.last_sweep = now
            q = self.hits[key]
            while q and now - q[0] >= 60:
                q.popleft()
            if len(q) >= self.per_minute:
                return False
            q.append(now)
            return True


def clients_from_env(env=os.environ):
    """Reputation lookups turn on only for services the operator configured a key for."""
    from .enrich import build_clients
    if not any(env.get(k) for k in ("VT_API_KEY", "ABUSEIPDB_API_KEY", "URLSCAN_API_KEY")):
        return {}
    from .enrich.cache import Cache
    cache_dir = Path(env.get("PHISHSCAN_CACHE_DIR") or Path.home() / ".phishscan")
    cache_dir.mkdir(parents=True, exist_ok=True)
    return build_clients(env, Cache(str(cache_dir / "cache.sqlite")))


def _truthy(name: str) -> bool:
    return os.environ.get(name, "").lower() in ("1", "true", "yes")


def _load_secret(db_path) -> str:
    if os.environ.get("PHISHSCAN_SECRET"):
        return os.environ["PHISHSCAN_SECRET"]
    if db_path and str(db_path) != ":memory:":
        f = Path(str(db_path) + ".secret")
        try:
            if f.exists():
                return f.read_text().strip()
            f.parent.mkdir(parents=True, exist_ok=True)
            key = secrets.token_hex(32)
            f.write_text(key)
            try:
                f.chmod(0o600)
            except OSError:
                pass
            return key
        except OSError:
            pass
    return secrets.token_hex(32)


def _safe_next(target: str) -> str:
    return target if target.startswith("/") and not target.startswith("//") and "\\" not in target else "/"


def _csv_safe(value) -> str:
    text = str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def _csv_response(rows, header, filename) -> Response:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(header)
    w.writerows([[_csv_safe(c) for c in r] for r in rows])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


def create_app(clients=None, max_upload_mb=None, rate_limit=None, store=None, password=_UNSET,
               api_token=_UNSET, secret_key=None, retention_days=None) -> Flask:
    app = Flask(__name__)
    app.jinja_env.autoescape = True
    here = Path(__file__).parent  # static/ is searchable so standalone pages can inline app.css
    app.jinja_env.loader = FileSystemLoader([str(here / "templates"), str(here / "static")])
    app.jinja_env.filters["defang"] = defang
    app.jinja_env.globals["STATUS_LABELS"] = STATUS_LABELS
    app.jinja_env.filters["short_ts"] = lambda v: (v or "")[:16].replace("T", " ") + " UTC"
    max_mb = max_upload_mb or int(os.environ.get("MAX_UPLOAD_MB", "10"))
    app.config["MAX_CONTENT_LENGTH"] = max_mb * 1024 * 1024
    rate = rate_limit or int(os.environ.get("PHISHSCAN_RATE_LIMIT", "60"))
    limiter, login_limiter = RateLimit(rate), RateLimit(8)
    password = os.environ.get("PHISHSCAN_PASSWORD") or None if password is _UNSET else (password or None)
    api_token = os.environ.get("PHISHSCAN_API_TOKEN") or None if api_token is _UNSET else (api_token or None)
    retention = retention_days if retention_days is not None else int(os.environ.get("PHISHSCAN_RETENTION_DAYS") or 0)
    if store is None:
        store = Store(os.path.expanduser(os.environ.get("PHISHSCAN_DB") or ":memory:"))
    if clients is None:
        clients = {} if _truthy("PHISHSCAN_OFFLINE") else clients_from_env()
    if _truthy("PHISHSCAN_TRUST_PROXY"):
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    db_path = getattr(store, "path", None)
    app.secret_key = secret_key or _load_secret(db_path)
    app.config.update(SESSION_COOKIE_NAME="phishscan_session", SESSION_COOKIE_HTTPONLY=True,
                      SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_SECURE=_truthy("PHISHSCAN_COOKIE_SECURE"),
                      PERMANENT_SESSION_LIFETIME=12 * 3600)
    app.extensions["phishscan_store"] = store
    purge_state = {"at": 0.0}

    # ---------------- helpers ----------------
    def csrf_token() -> str:
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        return session["csrf"]

    def wants_json() -> bool:
        return request.path.startswith("/api/") or request.accept_mimetypes.best == "application/json"

    def fail(code: int, message: str):
        if wants_json():
            return jsonify(error=message), code
        page = render_template("error.html", home_href="/", code=code, message=message, version=__version__)
        return Response(page, status=code, mimetype="text/html")

    def authed() -> bool:
        if not password:
            return True
        if session.get("auth"):
            return True
        if api_token and request.path.startswith("/api/"):
            got = request.headers.get("Authorization", "")
            return got.startswith("Bearer ") and hmac.compare_digest(got[7:], api_token)
        return False

    @app.context_processor
    def inject():
        return {"csrf_token": csrf_token, "version": __version__, "lookups": bool(clients),
                "auth_enabled": bool(password), "STATUS_LABELS": STATUS_LABELS, "max_mb": max_mb,
                "status_labels": STATUS_LABELS, "open_count": store.open_count(), "samples": SAMPLES,
                "url_with": url_with}

    def url_with(**changes):
        args = {k: v for k, v in request.args.items()}
        for k, v in changes.items():
            if v is None or v == "":
                args.pop(k, None)
            else:
                args[k] = v
        return url_for(request.endpoint, **args)

    # ---------------- request pipeline ----------------
    @app.before_request
    def gate():
        if retention and time.monotonic() - purge_state["at"] > 6 * 3600:
            purge_state["at"] = time.monotonic()
            store.purge_older_than(retention)
        ip = request.remote_addr or "?"
        if request.method == "POST" and not limiter.allow(ip):
            return fail(429, "Too many requests. Please wait a minute and try again.")
        if request.endpoint in _PUBLIC or request.endpoint is None:
            return None
        if not authed():
            if wants_json():
                return fail(401, "Authentication required.")
            return redirect(url_for("login", next=request.full_path.rstrip("?")))
        if request.method == "POST" and not request.path.startswith("/api/"):
            sent = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
            if not hmac.compare_digest(sent, session.get("csrf", "")):
                return fail(400, "Your session expired or the request could not be verified. Reload the page and try again.")
        return None

    @app.after_request
    def secure(resp):
        resp.headers.setdefault("Content-Security-Policy", CSP)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        if request.endpoint != "static":
            resp.headers["Cache-Control"] = "no-store"
        if app.config["SESSION_COOKIE_SECURE"]:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return resp

    # ---------------- auth ----------------
    @app.route("/login", methods=["GET", "POST"])
    def login():
        nxt = _safe_next(request.values.get("next", "/"))
        if not password or session.get("auth"):
            return redirect(nxt)
        if request.method == "POST":
            if not hmac.compare_digest(request.form.get("csrf_token", ""), session.get("csrf", "")):
                return fail(400, "Your session expired. Reload the page and try again.")
            if not login_limiter.allow(request.remote_addr or "?"):
                return fail(429, "Too many sign-in attempts. Please wait a minute.")
            if hmac.compare_digest(request.form.get("password", "").encode(), password.encode()):
                session.clear()
                session.permanent = True
                session["auth"] = True
                csrf_token()
                log.info("login ok from %s", request.remote_addr)
                return redirect(nxt)
            log.warning("login failed from %s", request.remote_addr)
            return Response(render_template("login.html", next=nxt, error="That password is not correct."),
                            status=401, mimetype="text/html")
        return render_template("login.html", next=nxt, error=None)

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.get("/healthz")
    def healthz():
        return jsonify(status="ok", version=__version__)

    # ---------------- dashboard ----------------
    @app.get("/")
    def dashboard():
        stats = store.stats(14)
        series = stats["series"]
        recent, _ = store.list(limit=6)
        top = stats["top_rules"]
        top_max = max([r["count"] for r in top] + [1])
        sparks = {k: (sparkline([d[k] for d in series]) if any(d[k] for d in series) else "")
                  for k in ("total", "malicious", "suspicious")}
        return render_template(
            "dashboard.html", active="dashboard", stats=stats, chart=activity_chart(series), donut=donut(stats),
            sparks=sparks, recent=recent, recent_total=sum(d["total"] for d in series),
            mal_pct=round(100 * stats["malicious"] / stats["total"]) if stats["total"] else 0,
            new_count=store.list(status="new", limit=1)[1],
            top_rules=[{"title": rule_title(r["rule"]), "count": r["count"], "pct": round(100 * r["count"] / top_max)}
                       for r in top])

    # ---------------- analysis ----------------
    @app.get("/analyze")
    def analyze_page():
        return render_template("analyze.html", active="analyze")

    def read_upload() -> bytes:
        if "eml" in request.files:
            return request.files["eml"].read()
        if request.form.get("raw", "").strip():
            return request.form["raw"].encode("utf-8", errors="replace")
        if request.files:
            raise ValueError("Upload the email in a form field named 'eml'.")
        if request.mimetype in ("message/rfc822", "application/octet-stream", "text/plain") and request.get_data():
            return request.get_data()
        raise ValueError("No email received. Choose an .eml file or paste the raw message.")

    def analyze_and_save(data: bytes):
        result = analyze_bytes(data, clients or None)
        cid, dup = store.add(result)
        log.info("analyzed case=%s sha256=%s verdict=%s score=%s dup=%s", cid, result.email_sha256[:12],
                 result.verdict.label, result.verdict.score, dup)
        return cid, dup

    def saved_response(cid: int, dup: bool):
        if wants_json():
            return jsonify(id=cid, duplicate=dup, url=url_for("case_detail", case_id=cid))
        return redirect(url_for("case_detail", case_id=cid, dup=1 if dup else None), code=303)

    @app.post("/analyze")
    def analyze_upload():
        try:
            return saved_response(*analyze_and_save(read_upload()))
        except ValueError as exc:
            return fail(400, str(exc))

    @app.post("/samples/<name>")
    def analyze_sample(name):
        if name not in SAMPLES:
            return fail(404, "Unknown sample.")
        return saved_response(*analyze_and_save(sample_bytes(name)))

    @app.post("/demo/seed")
    def seed_demo_data():
        seed_demo(store)
        return redirect(url_for("dashboard", seeded=1), code=303)

    # ---------------- cases ----------------
    @app.get("/cases")
    def cases():
        verdict = request.args.get("verdict") if request.args.get("verdict") in VERDICTS else None
        status = request.args.get("status") if request.args.get("status") in STATUSES else None
        q = request.args.get("q", "").strip()[:200]
        page = max(1, request.args.get("page", 1, type=int) or 1)
        rows, total = store.list(verdict=verdict, status=status, q=q or None, limit=PER_PAGE,
                                 offset=(page - 1) * PER_PAGE)
        return render_template("cases.html", active="cases", rows=rows, total=total, page=page,
                               pages=max(1, math.ceil(total / PER_PAGE)), verdict=verdict, status=status, q=q)

    def load_case(case_id):
        case = store.get(case_id)
        return case

    @app.get("/cases/<int:case_id>")
    def case_detail(case_id):
        case = load_case(case_id)
        if not case:
            return fail(404, "That case does not exist. It may have been deleted.")
        return render_template("case.html", active="cases", case=case, r=case["ctx"])

    @app.get("/cases/<int:case_id>/report.html")
    def case_report(case_id):
        case = load_case(case_id)
        if not case:
            return fail(404, "That case does not exist.")
        resp = Response(render_report_html(case["ctx"]), mimetype="text/html")
        resp.headers["Content-Security-Policy"] = REPORT_CSP
        if request.args.get("download"):
            resp.headers["Content-Disposition"] = f'attachment; filename="phishscan-case-{case_id}.html"'
        return resp

    @app.get("/cases/<int:case_id>/report.json")
    def case_json(case_id):
        case = load_case(case_id)
        if not case:
            return fail(404, "That case does not exist.")
        body = {"case": {k: case[k] for k in ("id", "created_at", "status", "notes", "sha256")}, "analysis": case["ctx"]}
        return Response(json.dumps(body, indent=2), mimetype="application/json",
                        headers={"Content-Disposition": f'attachment; filename="phishscan-case-{case_id}.json"'})

    @app.get("/cases/<int:case_id>/iocs.csv")
    def case_iocs_csv(case_id):
        if not load_case(case_id):
            return fail(404, "That case does not exist.")
        raw = request.args.get("raw") == "1"
        rows = [(r["kind"], r["value"] if raw else defang(r["value"])) for r in store.case_iocs(case_id)]
        return _csv_response(rows, ["type", "indicator"], f"phishscan-case-{case_id}-indicators.csv")

    def json_body() -> dict:
        data = request.get_json(silent=True)
        return data if isinstance(data, dict) else {}

    @app.post("/cases/<int:case_id>/status")
    def case_status(case_id):
        try:
            ok = store.update(case_id, status=json_body().get("status"))
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        return (jsonify(ok=True), 200) if ok else (jsonify(error="No such case."), 404)

    @app.post("/cases/<int:case_id>/notes")
    def case_notes(case_id):
        notes = json_body().get("notes")
        if not isinstance(notes, str):
            return jsonify(error="Notes must be text."), 400
        try:
            ok = store.update(case_id, notes=notes)
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        return (jsonify(ok=True), 200) if ok else (jsonify(error="No such case."), 404)

    @app.post("/cases/<int:case_id>/delete")
    def case_delete(case_id):
        store.delete(case_id)
        return redirect(url_for("cases", deleted=1), code=303)

    # ---------------- indicators ----------------
    def ioc_filters():
        kind = request.args.get("kind") if request.args.get("kind") in ("URL", "Domain", "IP", "Hash") else None
        return kind, request.args.get("q", "").strip()[:200]

    @app.get("/indicators")
    def indicators():
        kind, q = ioc_filters()
        page = max(1, request.args.get("page", 1, type=int) or 1)
        rows, total = store.iocs(kind=kind, q=q or None, limit=IOC_PER_PAGE, offset=(page - 1) * IOC_PER_PAGE)
        return render_template("iocs.html", active="iocs", rows=rows, total=total, page=page,
                               pages=max(1, math.ceil(total / IOC_PER_PAGE)), kind=kind, q=q)

    @app.get("/indicators.csv")
    def indicators_csv():
        kind, q = ioc_filters()
        raw = request.args.get("raw") == "1"
        rows, _ = store.iocs(kind=kind, q=q or None, limit=100000)
        data = [(r["kind"], r["value"] if raw else defang(r["value"]), r["cases"], r["max_score"], r["first_seen"],
                 r["last_seen"]) for r in rows]
        return _csv_response(data, ["type", "indicator", "cases", "max_score", "first_seen", "last_seen"],
                             "phishscan-indicators.csv")

    # ---------------- settings ----------------
    @app.get("/settings")
    def settings():
        providers = [{"name": n, "env": e, "on": k in clients} for n, e, k in
                     (("VirusTotal", "VT_API_KEY", "virustotal"), ("AbuseIPDB", "ABUSEIPDB_API_KEY", "abuseipdb"),
                      ("URLScan", "URLSCAN_API_KEY", "urlscan"))]
        rules = sorted(({"id": k, "title": rule_title(k), "points": v, "mitre": RULE_TO_TECHNIQUE.get(k)}
                        for k, v in WEIGHTS.items()), key=lambda r: -r["points"])
        storage = "In memory (cleared when the server restarts)" if not db_path or str(db_path) == ":memory:" \
            else f"SQLite file: {db_path}"
        return render_template("settings.html", active="settings", providers=providers, rules=rules, storage=storage,
                               api_token=bool(api_token), rate_limit=rate, retention=retention,
                               stats_total=store.stats(1)["total"])

    @app.post("/settings/purge")
    def purge():
        store.purge_all()
        return redirect(url_for("dashboard", purged=1), code=303)

    # ---------------- JSON API (stateless) ----------------
    @app.post("/api/analyze")
    def api_analyze():
        try:
            return Response(render_json(analyze_bytes(read_upload(), clients or None)), mimetype="application/json")
        except ValueError as exc:
            return fail(400, str(exc))

    @app.get("/api/stats")
    def api_stats():
        return jsonify(store.stats(14))

    # ---------------- errors ----------------
    @app.errorhandler(413)
    def too_large(_):
        return fail(413, f"The file is too large (limit {max_mb} MB).")

    @app.errorhandler(Exception)
    def crash(exc):
        if isinstance(exc, HTTPException):
            messages = {404: "Page not found.", 405: "That URL does not accept this kind of request."}
            return fail(exc.code or 500, messages.get(exc.code, exc.description or "Request failed."))
        log.exception("unhandled error")
        return fail(500, "Something went wrong while handling that request. Nothing was changed.")

    return app


def serve(host: str = "127.0.0.1", port: int = 8000, threads: int = 4, demo: bool = False) -> None:
    from waitress import serve as _serve
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    password = os.environ.get("PHISHSCAN_PASSWORD")
    if host not in ("127.0.0.1", "localhost", "::1") and not password and not _truthy("PHISHSCAN_ALLOW_NO_AUTH"):
        raise SystemExit("Refusing to listen on a network address without a password.\n"
                         "Set PHISHSCAN_PASSWORD (recommended), or PHISHSCAN_ALLOW_NO_AUTH=1 if something else "
                         "already protects this server.")
    if demo:
        store = Store(":memory:")
        seed_demo(store)
    else:
        path = os.path.expanduser(os.environ.get("PHISHSCAN_DB") or str(Path.home() / ".phishscan" / "phishscan.db"))
        store = Store(":memory:" if _truthy("PHISHSCAN_MEMORY_ONLY") else path)
    app = create_app(store=store)
    log.info("PhishScan %s on http://%s:%s (%s)", __version__, host, port,
             "demo data, in memory" if demo else "password protected" if password else "no password")
    _serve(app, host=host, port=port, threads=threads)
