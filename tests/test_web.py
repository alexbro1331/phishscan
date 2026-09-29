import io
import json
import re

import pytest

from phishscan.store import Store
from phishscan.web import RateLimit, create_app
from tests.helpers import build_eml

PHISH = dict(from_="PayPal <s@paypa1.com>", auth="mx; spf=fail; dkim=fail; dmarc=fail",
             text="URGENT verify your account immediately http://bit.ly/x")
PASS = "mx; spf=pass; dkim=pass; dmarc=pass"


def make(**kw):
    kw.setdefault("clients", {})
    kw.setdefault("store", Store(":memory:"))
    kw.setdefault("rate_limit", 1000)
    kw.setdefault("password", None)
    kw.setdefault("api_token", None)
    kw.setdefault("secret_key", "test")
    app = create_app(**kw)
    return app, app.test_client()


def token(c):
    html = c.get("/").get_data(as_text=True)
    return re.search(r'name="csrf-token" content="([^"]+)"', html).group(1)


def upload(c, data, tok=None, name="a.eml", path="/analyze", **kw):
    tok = tok or token(c)
    return c.post(path, data={"eml": (io.BytesIO(data), name), "csrf_token": tok},
                  content_type="multipart/form-data", **kw)


@pytest.fixture
def client():
    return make()[1]


# ---------------------------------------------------------------- pages
def test_every_page_renders_empty_and_populated(client):
    for path in ("/", "/analyze", "/cases", "/indicators", "/settings"):
        r = client.get(path)
        assert r.status_code == 200, path
        assert b"PhishScan" in r.data and b"<script>" not in r.data.lower()
    upload(client, build_eml(**PHISH), name="p.eml")
    for path in ("/", "/cases", "/indicators", "/cases/1", "/cases/1/report.html", "/settings"):
        assert client.get(path).status_code == 200, path


def test_dashboard_shows_kpis_chart_and_donut_after_data(client):
    upload(client, build_eml(**PHISH))
    html = client.get("/").get_data(as_text=True)
    assert 'data-count="1"' in html and "Activity, last 14 days" in html and 'class="donut"' in html
    assert "Malicious" in html and "Top detections" in html


def test_empty_dashboard_offers_samples_and_demo(client):
    html = client.get("/").get_data(as_text=True)
    assert "No analyses yet" in html and "Analyze: Credential phish" in html and "Load demo data" in html


def test_upload_creates_case_and_redirects_or_returns_json(client):
    tok = token(client)
    r = upload(client, build_eml(**PHISH), tok)
    assert r.status_code == 303 and r.headers["Location"].endswith("/cases/1")
    j = upload(client, build_eml(subject="another", auth=PASS), tok, headers={"Accept": "application/json"})
    assert j.status_code == 200 and j.get_json()["id"] == 2 and j.get_json()["duplicate"] is False
    again = upload(client, build_eml(**PHISH), tok, headers={"Accept": "application/json"})
    assert again.get_json() == {"id": 1, "duplicate": True, "url": "/cases/1"}


def test_paste_raw_message_and_samples(client):
    tok = token(client)
    raw = build_eml(**PHISH).decode()
    r = client.post("/analyze", data={"raw": raw, "csrf_token": tok}, headers={"Accept": "application/json"})
    assert r.status_code == 200 and r.get_json()["id"] == 1
    s = client.post("/samples/credential-phish", data={"csrf_token": tok}, headers={"Accept": "application/json"})
    assert s.status_code == 200
    assert client.post("/samples/nope", data={"csrf_token": tok}).status_code == 404


def test_bad_uploads_give_clear_errors(client):
    tok = token(client)
    assert client.post("/analyze", data={"csrf_token": tok}).status_code == 400
    empty = upload(client, b"", tok, headers={"Accept": "application/json"})
    assert empty.status_code == 400 and "empty" in empty.get_json()["error"].lower()
    junk = upload(client, b"\x00\x01 not an email", tok)
    assert junk.status_code == 400 and b"does not look like an email" in junk.data
    big = upload(client, b"From: a@b.com\r\n\r\n" + b"x" * (12 * 1024 * 1024), tok)
    assert big.status_code == 413 and b"too large" in big.data.lower()


# ---------------------------------------------------------------- case management
def test_status_notes_and_delete_flow(client):
    tok = token(client)
    upload(client, build_eml(**PHISH), tok)
    h = {"X-CSRF-Token": tok}
    assert client.post("/cases/1/status", json={"status": "investigating"}, headers=h).status_code == 200
    assert client.post("/cases/1/status", json={"status": "banana"}, headers=h).status_code == 400
    assert client.post("/cases/1/notes", json={"notes": "Called the user."}, headers=h).status_code == 200
    assert client.post("/cases/1/notes", json={"notes": "x" * 20001}, headers=h).status_code == 400
    assert client.post("/cases/1/notes", json={"notes": 5}, headers=h).status_code == 400
    assert client.post("/cases/99/status", json={"status": "resolved"}, headers=h).status_code == 404
    page = client.get("/cases/1").get_data(as_text=True)
    assert "Called the user." in page and 'value="investigating" selected' in page
    assert client.post("/cases/1/delete", data={"csrf_token": tok}).status_code == 303
    assert client.get("/cases/1").status_code == 404


def test_cases_filtering_and_pagination(client):
    tok = token(client)
    for i in range(23):
        upload(client, build_eml(subject=f"Lunch {i}", auth=PASS), tok)
    upload(client, build_eml(**PHISH), tok)
    page1 = client.get("/cases").get_data(as_text=True)
    assert "Page 1 of 2" in page1 and "24 cases" in page1
    assert "Page 2 of 2" in client.get("/cases?page=2").get_data(as_text=True)
    only = client.get("/cases?verdict=Malicious").get_data(as_text=True)
    assert "1 case" in only and "Lunch" not in only
    assert "No cases match" in client.get("/cases?q=zzzznothing").get_data(as_text=True)
    assert client.get("/cases?page=abc&verdict=Bogus&status=Bogus").status_code == 200


def test_exports_report_json_and_csv(client):
    upload(client, build_eml(**PHISH))
    rep = client.get("/cases/1/report.html?download=1")
    assert "attachment" in rep.headers["Content-Disposition"] and b"<script" not in rep.data.lower()
    assert "script-src 'none'" in rep.headers["Content-Security-Policy"]
    data = json.loads(client.get("/cases/1/report.json").data)
    assert data["case"]["id"] == 1 and data["analysis"]["label"] == "Malicious"
    csv_def = client.get("/cases/1/iocs.csv").get_data(as_text=True)
    csv_raw = client.get("/cases/1/iocs.csv?raw=1").get_data(as_text=True)
    assert "hxxp://bit[.]ly/x" in csv_def and "http://bit.ly/x" in csv_raw and "http://bit.ly/x" not in csv_def
    allcsv = client.get("/indicators.csv").get_data(as_text=True)
    assert allcsv.startswith("type,indicator,cases,max_score") and "bit[.]ly" in allcsv
    assert "http://bit.ly/x" in client.get("/indicators.csv?raw=1").get_data(as_text=True)


def test_demo_seed_and_purge(client):
    tok = token(client)
    assert client.post("/demo/seed", data={"csrf_token": tok}).status_code == 303
    assert "Recent cases" in client.get("/").get_data(as_text=True)
    assert client.post("/settings/purge", data={"csrf_token": tok}).status_code == 303
    assert "No analyses yet" in client.get("/").get_data(as_text=True)


def test_untrusted_email_content_is_escaped_everywhere(client):
    tok = token(client)
    upload(client, build_eml(subject="<script>alert(1)</script>", from_='"<img src=x onerror=alert(1)>" <a@b.com>',
                             text="see http://evil.com/<script>x</script>"), tok)
    for path in ("/", "/cases", "/cases/1", "/cases/1/report.html", "/indicators"):
        html = client.get(path).get_data(as_text=True)
        assert "<script>alert(1)" not in html and "<img src=x" not in html, path


# ---------------------------------------------------------------- security
def test_post_without_csrf_token_is_rejected(client):
    upload(client, build_eml(**PHISH))
    assert client.post("/cases/1/delete").status_code == 400
    assert client.post("/cases/1/status", json={"status": "resolved"}).status_code == 400
    assert client.post("/analyze", data={"csrf_token": "wrong"}).status_code == 400
    assert client.get("/cases/1").status_code == 200          # nothing was deleted


def test_security_headers_and_no_store(client):
    r = client.get("/")
    assert r.headers["Cache-Control"] == "no-store"
    assert r.headers["X-Content-Type-Options"] == "nosniff" and r.headers["X-Frame-Options"] == "DENY"
    csp = r.headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp and "'unsafe-inline'" not in csp.split("script-src")[1].split(";")[0]
    assert "frame-ancestors 'none'" in csp


def _login_token(c):
    return re.search(r'name="csrf_token" value="([^"]+)"', c.get("/login").get_data(as_text=True)).group(1)


def test_password_protection_and_login_flow():
    app, c = make(password="s3cret-pass")
    r = c.get("/cases")
    assert r.status_code == 302 and "/login" in r.headers["Location"]
    assert c.get("/healthz").status_code == 200                       # health check stays public
    assert c.get("/static/app.css").status_code == 200
    tok = _login_token(c)
    bad = c.post("/login", data={"password": "nope", "csrf_token": tok})
    assert bad.status_code == 401 and b"not correct" in bad.data
    assert c.post("/login", data={"password": "s3cret-pass"}).status_code == 400    # no csrf token
    ok = c.post("/login", data={"password": "s3cret-pass", "csrf_token": tok, "next": "/cases"})
    assert ok.status_code == 302 and ok.headers["Location"].endswith("/cases")
    assert c.get("/cases").status_code == 200
    c.post("/logout", data={"csrf_token": token(c)})
    assert c.get("/cases").status_code == 302


def test_login_redirect_cannot_leave_the_site():
    app, c = make(password="pw")
    r = c.post("/login", data={"password": "pw", "csrf_token": _login_token(c), "next": "//evil.example/x"})
    assert r.status_code == 302 and "evil.example" not in r.headers["Location"]


def test_login_is_rate_limited():
    app, c = make(password="pw")
    tok = _login_token(c)
    codes = [c.post("/login", data={"password": "bad", "csrf_token": tok}).status_code for _ in range(12)]
    assert 429 in codes and codes[0] == 401


def test_api_requires_token_when_password_set_and_is_stateless():
    app, c = make(password="pw", api_token="tok123")
    body = build_eml(**PHISH)
    assert c.post("/api/analyze", data=body, content_type="message/rfc822").status_code == 401
    ok = c.post("/api/analyze", data=body, content_type="message/rfc822", headers={"Authorization": "Bearer tok123"})
    assert ok.status_code == 200 and ok.get_json()["verdict"]["label"] == "Malicious"
    bad = c.post("/api/analyze", data=body, content_type="message/rfc822", headers={"Authorization": "Bearer wrong"})
    assert bad.status_code == 401
    assert app.extensions["phishscan_store"].stats()["total"] == 0        # API never stores anything


def test_api_open_when_no_password_and_json_errors(client):
    r = client.post("/api/analyze", data=build_eml(**PHISH), content_type="message/rfc822")
    assert r.status_code == 200
    e = client.post("/api/analyze", data=b"", content_type="message/rfc822")
    assert e.status_code == 400 and "error" in e.get_json()
    assert client.get("/api/stats").get_json()["total"] == 0


def test_rate_limit():
    app, c = make(rate_limit=3)
    tok = token(c)
    codes = [c.post("/analyze", data={"csrf_token": tok}).status_code for _ in range(5)]
    assert codes[-1] == 429


def test_rate_limit_table_does_not_grow_forever():
    t = [0.0]
    rl = RateLimit(5, clock=lambda: t[0])
    for i in range(50):
        rl.allow(f"10.0.0.{i}")
    t[0] = 120
    rl.allow("10.9.9.9")
    assert len(rl.hits) <= 2


def test_unknown_page_and_unexpected_errors_are_clean(monkeypatch):
    app, c = make()
    r = c.get("/nope")
    assert r.status_code == 404 and b"Page not found" in r.data
    import phishscan.web as web
    monkeypatch.setattr(web, "analyze_bytes", lambda *a, **k: 1 / 0)
    app2, c2 = make()
    r = upload(c2, build_eml())
    assert r.status_code == 500 and b"ZeroDivisionError" not in r.data and b"Traceback" not in r.data


def test_retention_purges_old_cases_on_first_request():
    from tests.test_store import phish
    store = Store(":memory:", clock=lambda: "2026-01-01T00:00:00Z")
    store.add(phish())
    store.clock = lambda: "2026-09-29T00:00:00Z"
    app, c = make(store=store, retention_days=30)
    c.get("/")
    assert store.stats()["total"] == 0


def test_serve_refuses_open_network_listener_without_password(monkeypatch):
    import phishscan.web as web
    monkeypatch.delenv("PHISHSCAN_PASSWORD", raising=False)
    monkeypatch.delenv("PHISHSCAN_ALLOW_NO_AUTH", raising=False)
    with pytest.raises(SystemExit) as e:
        web.serve(host="0.0.0.0", port=1)
    assert "PHISHSCAN_PASSWORD" in str(e.value)


def test_retention_runs_on_first_request_even_right_after_boot(monkeypatch):
    """The clean-up timer must not depend on how long the machine has been up (regression: CI runners)."""
    import phishscan.web as web
    from tests.test_store import phish
    monkeypatch.setattr(web.time, "monotonic", lambda: 5.0)          # a machine that booted 5 seconds ago
    store = Store(":memory:", clock=lambda: "2026-01-01T00:00:00Z")
    store.add(phish())
    store.clock = lambda: "2026-09-29T00:00:00Z"
    app, c = make(store=store, retention_days=30)
    c.get("/")
    assert store.stats()["total"] == 0
