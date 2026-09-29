from phishscan.demo import seed_demo
from phishscan.store import Store


def test_demo_seed_creates_realistic_mix_over_two_weeks():
    store = Store(":memory:")
    n = seed_demo(store, days=14)
    s = store.stats(days=14)
    assert n == s["total"] >= 20
    assert s["malicious"] > 0 and s["suspicious"] > 0 and s["safe"] > 0
    assert sum(1 for d in s["series"] if d["total"] > 0) >= 8      # spread across many days
    assert len(s["top_rules"]) >= 5 and store.iocs()[1] > 10
    assert seed_demo(store, days=14) == 0                          # idempotent: same emails, no duplicates
