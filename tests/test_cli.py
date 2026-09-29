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
