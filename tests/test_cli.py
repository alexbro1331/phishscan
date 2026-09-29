from phishscan.cli import main

BAD = dict(from_="PayPal <s@paypa1.com>", auth="mx; spf=fail; dkim=fail; dmarc=fail",
           text="URGENT verify your account immediately http://bit.ly/x")


def test_cli_malicious_exit_code_and_files(write_eml, tmp_path, capsys):
    eml = write_eml(**BAD)
    out = tmp_path / "r.html"
    code = main([str(eml), "--offline", "-o", str(out), "--json"])
    assert code == 2 and out.exists() and out.with_suffix(".json").exists()
    printed = capsys.readouterr().out
    assert "Malicious" in printed and "http://bit.ly" not in printed


def test_cli_clean_exit_zero(write_eml, tmp_path):
    eml = write_eml(auth="mx; spf=pass; dkim=pass; dmarc=pass")
    assert main([str(eml), "--offline", "-o", str(tmp_path / "r.html")]) == 0


def test_cli_missing_file(tmp_path, capsys):
    assert main([str(tmp_path / "nope.eml"), "--offline"]) == 3
    assert "not found" in capsys.readouterr().err.lower()


def test_cli_invalid_email_file_is_clean_error(tmp_path, capsys):
    bad = tmp_path / "junk.eml"
    bad.write_bytes(b"\x00\x01 not an email")
    assert main([str(bad), "--offline"]) == 3
    assert "does not look like an email" in capsys.readouterr().err


def test_cli_batch_folder(write_eml, tmp_path, capsys):
    import csv
    from tests.helpers import build_eml
    src = tmp_path / "inbox"
    src.mkdir()
    (src / "bad.eml").write_bytes(build_eml(**BAD))
    (src / "good.eml").write_bytes(build_eml(auth="mx; spf=pass; dkim=pass; dmarc=pass"))
    (src / "junk.eml").write_bytes(b"\x00\x01 garbage")
    out = tmp_path / "out"
    code = main([str(src), "--offline", "-o", str(out)])
    assert code == 2  # worst verdict wins; unreadable file does not abort the run
    assert (out / "bad.report.html").exists() and (out / "good.report.html").exists()
    assert (out / "index.html").exists()
    rows = {r["file"]: r for r in csv.DictReader((out / "summary.csv").open(encoding="utf-8"))}
    assert rows["bad.eml"]["verdict"] == "Malicious" and rows["good.eml"]["verdict"] == "Safe"
    assert rows["junk.eml"]["verdict"] == "Error"
    assert "3 emails" in capsys.readouterr().out


def test_cli_empty_folder(tmp_path, capsys):
    assert main([str(tmp_path), "--offline"]) == 3
    assert "no .eml files" in capsys.readouterr().err.lower()


def test_cli_serve_dispatch(monkeypatch):
    import phishscan.web as web
    seen = {}
    monkeypatch.setattr(web, "serve", lambda host, port, threads=4, demo=False: seen.update(host=host, port=port, threads=threads, demo=demo))
    assert main(["serve", "--host", "0.0.0.0", "--port", "9001"]) == 0
    assert seen == {"host": "0.0.0.0", "port": 9001, "threads": 4, "demo": False}


def test_cli_version(capsys):
    import pytest
    import phishscan
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0 and phishscan.__version__ in capsys.readouterr().out


def test_cli_serve_demo_and_threads_are_passed_through(monkeypatch):
    import phishscan.web as web
    seen = {}
    monkeypatch.setattr(web, "serve", lambda host, port, threads=4, demo=False: seen.update(threads=threads, demo=demo))
    assert main(["serve", "--demo", "--threads", "8"]) == 0
    assert seen == {"threads": 8, "demo": True}
