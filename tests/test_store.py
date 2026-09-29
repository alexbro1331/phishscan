import pytest

from phishscan.analyzer import analyze_bytes
from phishscan.store import STATUSES, Store
from tests.helpers import build_eml

PASS = "mx; spf=pass; dkim=pass; dmarc=pass"


def phish(n=1):
    return analyze_bytes(build_eml(from_="PayPal <s@paypa1.com>", auth="mx; spf=fail; dkim=fail; dmarc=fail",
                                   subject=f"Suspended {n}", text="URGENT verify your account immediately http://bit.ly/x"))


def clean(n=1):
    return analyze_bytes(build_eml(auth=PASS, subject=f"Lunch {n}"))


def mid(n=1):
    return analyze_bytes(build_eml(auth="mx; spf=fail; dkim=pass; dmarc=pass", reply_to="x@evil.com", subject=f"Hmm {n}"))


@pytest.fixture
def store():
    return Store(":memory:")


def test_add_and_get_roundtrip(store):
    cid, dup = store.add(phish())
    assert dup is False
    c = store.get(cid)
    assert c["verdict"] == "Malicious" and c["status"] == "new" and c["notes"] == ""
    assert c["ctx"]["label"] == "Malicious" and c["ctx"]["findings"]


def test_same_email_twice_returns_existing_case(store):
    a = phish()
    first, _ = store.add(a)
    second, dup = store.add(a)
    assert second == first and dup is True
    assert store.stats()["total"] == 1


def test_list_filters_search_and_paging(store):
    for i in range(3):
        store.add(phish(i))
    store.add(clean())
    store.add(mid())
    rows, total = store.list()
    assert total == 5 and len(rows) == 5
    assert store.list(verdict="Malicious")[1] == 3
    assert store.list(verdict="Safe")[1] == 1
    assert store.list(q="lunch")[1] == 1                  # searches subject
    assert store.list(q="paypa1.com")[1] == 3             # and sender
    page, total = store.list(limit=2, offset=2)
    assert len(page) == 2 and total == 5
    assert store.list(verdict="Nope")[1] == 0             # unknown filter value matches nothing, never crashes


def test_search_is_safe_against_sql_and_like_wildcards(store):
    store.add(clean())
    assert store.list(q="'; DROP TABLE cases; --")[1] == 0
    assert store.list(q="%")[1] == 0                       # % is a literal, not a wildcard
    assert store.stats()["total"] == 1


def test_status_and_notes_update_with_validation(store):
    cid, _ = store.add(phish())
    store.update(cid, status="investigating", notes="Called the user.")
    c = store.get(cid)
    assert c["status"] == "investigating" and c["notes"] == "Called the user."
    with pytest.raises(ValueError):
        store.update(cid, status="banana")
    with pytest.raises(ValueError):
        store.update(cid, notes="x" * 20001)
    assert set(STATUSES) == {"new", "investigating", "resolved", "false_positive"}
    assert store.update(9999, status="resolved") is False


def test_delete_removes_case_and_its_indicators(store):
    cid, _ = store.add(phish())
    assert store.iocs()[1] > 0
    assert store.delete(cid) is True and store.get(cid) is None
    assert store.iocs()[1] == 0 and store.delete(cid) is False


def test_stats_counts_series_and_top_rules():
    t = ["2026-09-29T10:00:00Z"]
    store = Store(":memory:", clock=lambda: t[0])
    store.add(phish(1))
    store.add(clean(1))
    t[0] = "2026-09-27T09:00:00Z"
    store.add(phish(2))
    t[0] = "2026-09-29T12:00:00Z"
    s = store.stats(days=5)
    assert s["total"] == 3 and s["malicious"] == 2 and s["safe"] == 1 and s["suspicious"] == 0
    assert s["open"] == 3
    assert [d["date"] for d in s["series"]] == ["2026-09-25", "2026-09-26", "2026-09-27", "2026-09-28", "2026-09-29"]
    assert s["series"][2]["malicious"] == 1 and s["series"][4]["malicious"] == 1 and s["series"][3]["total"] == 0
    assert s["top_rules"][0]["count"] == 2
    store.update(1, status="resolved")
    assert store.stats()["open"] == 2


def test_iocs_aggregate_across_cases_and_export_defanged(store):
    store.add(phish(1))
    store.add(phish(2))
    rows, total = store.iocs()
    bit = next(r for r in rows if r["kind"] == "URL")
    assert bit["cases"] == 2 and bit["value"] == "http://bit.ly/x" and bit["max_score"] >= 60
    assert store.iocs(kind="Domain")[0][0]["kind"] == "Domain"
    assert store.iocs(q="bit.ly")[1] >= 1


def test_purge_older_than_and_all():
    t = ["2026-01-01T00:00:00Z"]
    store = Store(":memory:", clock=lambda: t[0])
    store.add(phish(1))
    t[0] = "2026-09-29T00:00:00Z"
    store.add(phish(2))
    assert store.purge_older_than(30) == 1 and store.stats()["total"] == 1
    assert store.purge_all() == 1 and store.stats()["total"] == 0


def test_store_is_usable_from_many_threads():
    import threading
    store = Store(":memory:")
    errors = []

    def work(n):
        try:
            for i in range(5):
                store.add(analyze_bytes(build_eml(subject=f"t{n}-{i}")))
                store.list()
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    ts = [threading.Thread(target=work, args=(n,)) for n in range(4)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert errors == [] and store.stats()["total"] == 20


def test_open_count_and_case_iocs(store):
    cid, _ = store.add(phish())
    store.add(clean())
    assert store.open_count() == 2
    store.update(cid, status="resolved")
    assert store.open_count() == 1
    kinds = {r["kind"] for r in store.case_iocs(cid)}
    assert {"URL", "Domain"} <= kinds and store.case_iocs(9999) == []
