"""Small web front-end: upload an .eml, get the report. Emails are analyzed in memory and never stored."""
import logging
import os
import threading
import time
from collections import defaultdict, deque
from pathlib import Path

from flask import Flask, Response, jsonify, request
from werkzeug.exceptions import HTTPException

from . import __version__
from .analyzer import analyze_bytes
from .report import render_html, render_json, render_page

log = logging.getLogger("phishscan.web")

CSP = ("default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
       "form-action 'self'; base-uri 'none'; frame-ancestors 'none'")


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
    """Enable reputation lookups only when the operator configured API keys."""
    if not (env.get("VT_API_KEY") or env.get("ABUSEIPDB_API_KEY")):
        return {}
    from .enrich import build_clients
    from .enrich.cache import Cache
    cache_dir = Path(env.get("PHISHSCAN_CACHE_DIR") or Path.home() / ".phishscan")
    cache_dir.mkdir(parents=True, exist_ok=True)
    return build_clients(env, Cache(str(cache_dir / "cache.sqlite")))


def create_app(clients=None, max_upload_mb=None, rate_limit=None) -> Flask:
    app = Flask(__name__)
    max_mb = max_upload_mb or int(os.environ.get("MAX_UPLOAD_MB", "10"))
    app.config["MAX_CONTENT_LENGTH"] = max_mb * 1024 * 1024
    limiter = RateLimit(rate_limit or int(os.environ.get("PHISHSCAN_RATE_LIMIT", "30")))
    if clients is None:
        clients = {} if os.environ.get("PHISHSCAN_OFFLINE", "").lower() in ("1", "true", "yes") \
            else clients_from_env()
    if os.environ.get("PHISHSCAN_TRUST_PROXY", "").lower() in ("1", "true", "yes"):
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    def wants_json() -> bool:
        return request.path.startswith("/api/")

    def fail(code: int, message: str):
        if wants_json():
            return jsonify(error=message), code
        page = render_page("error.html.j2", home_href="/", code=code, message=message)
        return Response(page, status=code, mimetype="text/html")

    @app.after_request
    def secure(resp):
        resp.headers.setdefault("Content-Security-Policy", CSP)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.before_request
    def throttle():
        if request.method == "POST" and not limiter.allow(request.remote_addr or "?"):
            return fail(429, "Too many requests. Please wait a minute and try again.")

    @app.get("/")
    def index():
        return render_page("index.html.j2", home_href="/", max_mb=max_mb, lookups=bool(clients))

    @app.get("/healthz")
    def healthz():
        return jsonify(status="ok", version=__version__)

    def read_upload() -> bytes:
        if "eml" in request.files:
            return request.files["eml"].read()
        if request.files:
            raise ValueError("Upload the email in a form field named 'eml'.")
        if request.mimetype in ("message/rfc822", "application/octet-stream", "text/plain"):
            return request.get_data()
        raise ValueError("No email received. Choose an .eml file to upload.")

    def run():
        data = read_upload()
        result = analyze_bytes(data, clients or None)
        log.info("analyzed sha256=%s verdict=%s score=%s", result.email_sha256[:12],
                 result.verdict.label, result.verdict.score)
        return result

    @app.post("/analyze")
    def analyze_page():
        try:
            return Response(render_html(run()), mimetype="text/html")
        except ValueError as exc:
            return fail(400, str(exc))

    @app.post("/api/analyze")
    def analyze_api():
        try:
            return Response(render_json(run()), mimetype="application/json")
        except ValueError as exc:
            return fail(400, str(exc))

    @app.errorhandler(413)
    def too_large(_):
        return fail(413, f"The file is too large (limit {max_mb} MB).")

    @app.errorhandler(404)
    def not_found(_):
        return fail(404, "Page not found.")

    @app.errorhandler(405)
    def bad_method(_):
        return fail(405, "That URL only accepts uploads sent from the form.")

    @app.errorhandler(Exception)
    def crash(exc):
        if isinstance(exc, HTTPException):
            return fail(exc.code or 500, exc.description or "Request failed.")
        log.exception("unhandled error")
        return fail(500, "Something went wrong while analyzing that file. It was not stored.")

    return app


def serve(host: str = "127.0.0.1", port: int = 8000, threads: int = 4) -> None:
    from waitress import serve as _serve
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    log.info("PhishScan %s listening on http://%s:%s", __version__, host, port)
    _serve(create_app(), host=host, port=port, threads=threads)
