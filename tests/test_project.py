import re
from pathlib import Path

import phishscan

ROOT = Path(__file__).parent.parent


def test_version_matches_pyproject():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert re.search(rf'^version = "{re.escape(phishscan.__version__)}"', text, re.M)


def test_all_templates_exist():
    names = {p.name for p in (ROOT / "phishscan" / "templates").iterdir()}
    assert {"base.html.j2", "report.html.j2", "index.html.j2", "error.html.j2",
            "batch.html.j2", "style.css"} <= names


def test_secrets_are_git_ignored():
    ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert ".env" in ignore.splitlines()
