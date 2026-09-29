from phishscan.auth import analyze_auth
from phishscan.parser import ParsedEmail


def rules(findings):
    return {f.rule for f in findings}


def test_all_pass_no_findings():
    e = ParsedEmail(from_addr="a@x.com", auth_results="mx; spf=pass; dkim=pass; dmarc=pass")
    res, f = analyze_auth(e)
    assert res == {"spf": "pass", "dkim": "pass", "dmarc": "pass"} and f == []


def test_failures():
    e = ParsedEmail(from_addr="a@x.com", auth_results="mx; spf=fail; dkim=fail; dmarc=fail")
    assert rules(analyze_auth(e)[1]) == {"spf_fail", "dkim_fail", "dmarc_fail"}


def test_missing_auth_header():
    assert rules(analyze_auth(ParsedEmail(from_addr="a@x.com"))[1]) == {"no_auth_results"}


def test_no_from_does_not_crash():
    analyze_auth(ParsedEmail())


def test_reply_to_and_return_path_mismatch():
    e = ParsedEmail(from_addr="a@x.com", reply_to="b@evil.com", return_path="c@other.com",
                    auth_results="spf=pass; dkim=pass; dmarc=pass")
    assert rules(analyze_auth(e)[1]) == {"reply_to_mismatch", "return_path_mismatch"}


def test_display_name_spoof():
    e = ParsedEmail(from_display="support@paypal.com", from_addr="x@evil.com",
                    auth_results="spf=pass; dkim=pass; dmarc=pass")
    assert rules(analyze_auth(e)[1]) == {"display_name_spoof"}


def test_received_spf_fallback_when_no_auth_results():
    e = ParsedEmail(from_addr="a@x.com", received_spf="fail (sender not permitted)")
    res, f = analyze_auth(e)
    assert res.get("spf") == "fail" and "spf_fail" in rules(f)


def test_first_auth_results_header_wins():
    e = ParsedEmail(from_addr="a@x.com",
                    auth_results="mx1; spf=pass; dkim=pass; dmarc=pass mx2; spf=fail")
    assert analyze_auth(e)[0]["spf"] == "pass"


def test_subdomain_of_same_organization_is_aligned_not_a_mismatch():
    e = ParsedEmail(from_addr="news@acme-corp.com", reply_to="support@acme-corp.com",
                    return_path="bounce@mail.acme-corp.com", auth_results="spf=pass; dkim=pass; dmarc=pass")
    assert analyze_auth(e)[1] == []
    e2 = ParsedEmail(from_addr="news@mail.acme-corp.com", return_path="bounce@acme-corp.com",
                     auth_results="spf=pass; dkim=pass; dmarc=pass")
    assert analyze_auth(e2)[1] == []


def test_lookalike_suffix_is_not_aligned():
    e = ParsedEmail(from_addr="news@acme-corp.com", reply_to="x@evilacme-corp.com",
                    auth_results="spf=pass; dkim=pass; dmarc=pass")
    assert rules(analyze_auth(e)[1]) == {"reply_to_mismatch"}
