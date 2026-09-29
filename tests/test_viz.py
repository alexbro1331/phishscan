from phishscan.labels import RULE_TITLES, rule_title
from phishscan.viz import activity_chart, donut, sparkline
from phishscan.weights import WEIGHTS


def day(d, m=0, s=0, f=0):
    return {"date": d, "malicious": m, "suspicious": s, "safe": f, "total": m + s + f}


def test_every_scoring_rule_has_a_human_title():
    assert set(WEIGHTS) <= set(RULE_TITLES)
    assert rule_title("dmarc_fail") == "DMARC failed"
    assert rule_title("something_new") == "Something new"      # unknown rules degrade gracefully


def test_activity_chart_geometry_is_stacked_and_bounded():
    series = [day("2026-09-01", m=2, s=1, f=1), day("2026-09-02"), day("2026-09-03", f=4)]
    c = activity_chart(series, width=300, height=120)
    assert len(c["bars"]) == 3
    b0, b1, b2 = c["bars"]
    assert [s["cls"] for s in b0["segments"]] == ["malicious", "suspicious", "safe"]
    assert b1["segments"] == [] and b1["total"] == 0
    for b in c["bars"]:
        for s in b["segments"]:
            assert 0 <= s["y"] and s["y"] + s["h"] <= c["plot_h"] + 0.01 and s["h"] > 0
    assert c["max"] >= 4 and c["gridlines"][0]["label"] == "0"
    assert b2["segments"][0]["h"] > b0["segments"][0]["h"] * 0.9   # 4 safe is taller than 2 malicious


def test_activity_chart_empty_data_does_not_divide_by_zero():
    c = activity_chart([day("2026-09-01"), day("2026-09-02")])
    assert c["max"] >= 1 and all(b["segments"] == [] for b in c["bars"])


def test_donut_percentages_and_empty():
    d = donut({"malicious": 1, "suspicious": 1, "safe": 2})
    assert d["total"] == 4
    pct = {s["cls"]: s["pct"] for s in d["segments"]}
    assert pct == {"malicious": 25, "suspicious": 25, "safe": 50}
    assert abs(sum(s["dash"] for s in d["segments"]) - d["circ"]) < 0.5
    e = donut({"malicious": 0, "suspicious": 0, "safe": 0})
    assert e["total"] == 0 and e["segments"] == []


def test_sparkline_points():
    assert sparkline([1, 2, 3], width=60, height=20).count(",") == 3
    assert sparkline([], width=60, height=20) == ""
    flat = sparkline([0, 0, 0], width=60, height=20)          # flat line must not crash
    assert flat and "nan" not in flat.lower()
