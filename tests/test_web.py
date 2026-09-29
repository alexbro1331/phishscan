import json

import pytest

from phishscan.web import create_app
from tests.helpers import build_eml

PHISH = dict(from_="PayPal <s@paypa1.com>", auth="mx; spf=fail; dkim=fail; dmarc=fail",
             text="URGENT verify your account immediately http://bit.ly/x")


@pytest.fixture
def client():
    app = create_app(clients={}, max_upload_mb=1, rate_limit=1000)
    return app.test_client()


def upload(client, data, path="/analyze", name="a.eml"):
    import io
    return client.post(path, data={"eml": (io.BytesIO(data), name)}, content_type="multipart/form-data")


def test_index_page_and_health(client):
    r = client.get("/")
    assert r.status_code == 200 and b"PhishScan" in r.data and b'type="file"' in r.data
    assert b"<script" not in r.data.lower()
    h = client.get("/healthz")
    assert h.status_code == 200 and h.get_json()["status"] == "ok"


def test_analyze_returns_report_with_security_headers(client):
    r = upload(client, build_eml(**PHISH))
    assert r.status_code == 200 and b"Malicious" in r.data and b"hxxp://bit[.]ly/x" in r.data
    assert r.headers["Cache-Control"] == "no-store"
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert "default-src 'none'" in r.headers["Content-Security-Policy"]
    assert r.headers["X-Frame-Options"] == "DENY"


def test_api_returns_json(client):
    r = upload(client, build_eml(**PHISH), path="/api/analyze")
    assert r.status_code == 200 and r.get_json()["verdict"]["label"] == "Malicious"


def test_api_accepts_raw_body(client):
    r = client.post("/api/analyze", data=build_eml(**PHISH), content_type="message/rfc822")
    assert r.status_code == 200 and r.get_json()["verdict"]["score"] >= 60


def test_missing_empty_and_garbage_uploads_give_clear_errors(client):
    assert client.post("/analyze", data={}, content_type="multipart/form-data").status_code == 400
    assert upload(client, b"").status_code == 400
    bad = upload(client, b"\x00\x01 not an email")
    assert bad.status_code == 400 and b"does not look like an email" in bad.data
    assert upload(client, b"", path="/api/analyze").get_json()["error"]


def test_oversize_upload_rejected(client):
    r = upload(client, b"From: a@b.com\r\n\r\n" + b"x" * (2 * 1024 * 1024))
    assert r.status_code == 413 and b"too large" in r.data.lower()


def test_rate_limit():
    app = create_app(clients={}, rate_limit=2)
    c = app.test_client()
    codes = [upload(c, build_eml()).status_code for _ in range(4)]
    assert codes[:2] == [200, 200] and codes[-1] == 429


def test_untrusted_content_is_escaped_in_report(client):
    r = upload(client, build_eml(subject="<script>alert(1)</script>"))
    assert b"<script>alert(1)</script>" not in r.data


def test_get_on_analyze_not_allowed(client):
    assert client.get("/analyze").status_code == 405


def test_malformed_multipart_is_a_client_error_not_a_500(client):
    r = client.post("/analyze", data=b"--nope\r\ngarbage", content_type="multipart/form-data; boundary=zzz")
    assert r.status_code == 400 and b"Error 400" in r.data


def test_unknown_page_is_404_page(client):
    r = client.get("/nope")
    assert r.status_code == 404 and b"Page not found" in r.data


def test_unexpected_exception_returns_500_without_leaking(monkeypatch):
    import phishscan.web as web
    monkeypatch.setattr(web, "analyze_bytes", lambda *a, **k: 1 / 0)
    c = web.create_app(clients={}, rate_limit=100).test_client()
    r = upload(c, build_eml())
    assert r.status_code == 500 and b"ZeroDivisionError" not in r.data and b"Traceback" not in r.data


def test_rate_limit_table_does_not_grow_forever():
    from phishscan.web import RateLimit
    t = [0.0]
    rl = RateLimit(5, clock=lambda: t[0])
    for i in range(50):
        rl.allow(f"10.0.0.{i}")
    t[0] = 120
    rl.allow("10.9.9.9")
    assert len(rl.hits) <= 2
