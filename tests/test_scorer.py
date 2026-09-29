from phishscan.models import Finding
from phishscan.scorer import score


def F(rule, pts):
    return Finding(rule, pts, rule)


def test_thresholds():
    assert score([F("a", 29)]).label == "Safe"
    assert score([F("a", 30)]).label == "Suspicious"
    assert score([F("a", 59)]).label == "Suspicious"
    assert score([F("a", 60)]).label == "Malicious"


def test_dedupes_rules_and_caps():
    v = score([F("a", 40), F("a", 40)])
    assert v.score == 40 and len(v.findings) == 1
    assert score([F("a", 70), F("b", 70)]).score == 100


def test_empty_is_safe():
    assert score([]).score == 0 and score([]).label == "Safe"
