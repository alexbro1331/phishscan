import re
from pathlib import Path

import phishscan

ROOT = Path(__file__).parent.parent


def test_version_matches_pyproject():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert re.search(rf'^version = "{re.escape(phishscan.__version__)}"', text, re.M)


def test_all_templates_exist():
    names = {p.name for p in (ROOT / "phishscan" / "templates").iterdir()}
    assert {"layout_app.html", "layout_standalone.html", "report_standalone.html", "dashboard.html", "analyze.html",
            "cases.html", "case.html", "iocs.html", "settings.html", "login.html", "error.html", "batch.html",
            "_verdict.html", "_evidence.html", "_doit.html", "_dropzone.html", "_macros.html"} <= names


def test_secrets_are_git_ignored():
    ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert ".env" in ignore.splitlines()


def test_static_assets_and_samples_exist_and_are_packaged():
    static = {p.name for p in (ROOT / "phishscan" / "static").iterdir()}
    assert {"app.css", "app.js", "theme.js", "favicon.svg"} <= static
    assert {p.name for p in (ROOT / "phishscan" / "samples").iterdir()} >= {"credential-phish.eml", "legit-newsletter.eml"}
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    for pattern in ("templates/*", "static/*", "samples/*"):
        assert pattern in text
