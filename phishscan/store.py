"""Local case database (SQLite). Stores analysis results, never the email body or raw message."""
import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .report import build_context

STATUSES = ("new", "investigating", "resolved", "false_positive")
VERDICTS = ("Malicious", "Suspicious", "Safe")
MAX_NOTES = 20000

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL,
  sha256 TEXT NOT NULL UNIQUE,
  subject TEXT NOT NULL DEFAULT '', from_addr TEXT NOT NULL DEFAULT '',
  from_display TEXT NOT NULL DEFAULT '', to_addr TEXT NOT NULL DEFAULT '',
  verdict TEXT NOT NULL, score INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'new', notes TEXT NOT NULL DEFAULT '',
  ctx TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
  case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE, rule TEXT NOT NULL, points INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS iocs (
  case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE, kind TEXT NOT NULL, value TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cases_created ON cases(created_at);
CREATE INDEX IF NOT EXISTS idx_findings_rule ON findings(rule);
CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(kind, value);
"""

_LIST_COLS = "id, created_at, subject, from_addr, from_display, to_addr, verdict, score, status, sha256"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _like(text: str) -> str:
    return "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


class Store:
    def __init__(self, path=":memory:", clock=_now):
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.path = str(path)
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript(_SCHEMA)
        self.lock = threading.RLock()
        self.clock = clock

    # ---- writes -------------------------------------------------------
    def add(self, a, created_at=None):
        """Save an Analysis. Returns (case_id, already_existed)."""
        ctx = build_context(a)
        ctx["version"] = a.version
        with self.lock:
            row = self.db.execute("SELECT id FROM cases WHERE sha256=?", (a.email_sha256,)).fetchone()
            if row:
                return row["id"], True
            cur = self.db.execute(
                "INSERT INTO cases (created_at, sha256, subject, from_addr, from_display, to_addr, verdict, score, ctx)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (created_at or self.clock(), a.email_sha256, a.email.subject, a.email.from_addr, a.email.from_display,
                 a.email.to_addr, a.verdict.label, a.verdict.score, json.dumps(ctx)))
            cid = cur.lastrowid
            self.db.executemany("INSERT INTO findings VALUES (?,?,?)",
                                [(cid, f.rule, f.points) for f in a.verdict.findings])
            rows = [(cid, "URL", u) for u in a.iocs.urls] + [(cid, "Domain", d) for d in a.iocs.domains] \
                + [(cid, "IP", i) for i in a.iocs.ips] + [(cid, "Hash", h) for _, h in a.iocs.hashes]
            self.db.executemany("INSERT INTO iocs VALUES (?,?,?)", rows)
            self.db.commit()
            return cid, False

    def update(self, case_id: int, status=None, notes=None) -> bool:
        if status is not None and status not in STATUSES:
            raise ValueError(f"Unknown status: {status}")
        if notes is not None and len(notes) > MAX_NOTES:
            raise ValueError(f"Notes are too long (limit {MAX_NOTES} characters).")
        with self.lock:
            cur = self.db.execute("SELECT id FROM cases WHERE id=?", (case_id,)).fetchone()
            if not cur:
                return False
            if status is not None:
                self.db.execute("UPDATE cases SET status=? WHERE id=?", (status, case_id))
            if notes is not None:
                self.db.execute("UPDATE cases SET notes=? WHERE id=?", (notes, case_id))
            self.db.commit()
            return True

    def delete(self, case_id: int) -> bool:
        with self.lock:
            n = self.db.execute("DELETE FROM cases WHERE id=?", (case_id,)).rowcount
            self.db.commit()
            return n > 0

    def purge_all(self) -> int:
        with self.lock:
            n = self.db.execute("DELETE FROM cases").rowcount
            self.db.commit()
            return n

    def purge_older_than(self, days: int) -> int:
        now = datetime.strptime(self.clock(), "%Y-%m-%dT%H:%M:%SZ")
        cutoff = (now - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self.lock:
            n = self.db.execute("DELETE FROM cases WHERE created_at < ?", (cutoff,)).rowcount
            self.db.commit()
            return n

    # ---- reads --------------------------------------------------------
    def get(self, case_id: int):
        with self.lock:
            row = self.db.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["ctx"] = json.loads(d["ctx"])
        return d

    def list(self, verdict=None, status=None, q=None, limit=25, offset=0):
        where, args = [], []
        if verdict:
            where.append("verdict=?")
            args.append(verdict)
        if status:
            where.append("status=?")
            args.append(status)
        if q:
            where.append("(subject LIKE ? ESCAPE '\\' OR from_addr LIKE ? ESCAPE '\\' OR from_display LIKE ? ESCAPE '\\'"
                         " OR sha256 LIKE ? ESCAPE '\\')")
            args += [_like(q)] * 4
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        with self.lock:
            total = self.db.execute(f"SELECT COUNT(*) FROM cases {clause}", args).fetchone()[0]
            rows = self.db.execute(
                f"SELECT {_LIST_COLS} FROM cases {clause} ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
                [*args, int(limit), int(offset)]).fetchall()
        return [dict(r) for r in rows], total

    def stats(self, days: int = 14) -> dict:
        today = datetime.strptime(self.clock(), "%Y-%m-%dT%H:%M:%SZ").date()
        dates = [(today - timedelta(days=i)).isoformat() for i in range(days - 1, -1, -1)]
        with self.lock:
            by_verdict = dict(self.db.execute("SELECT verdict, COUNT(*) FROM cases GROUP BY verdict").fetchall())
            open_count = self.db.execute(
                "SELECT COUNT(*) FROM cases WHERE status IN ('new','investigating')").fetchone()[0]
            per_day = self.db.execute(
                "SELECT substr(created_at,1,10) d, verdict, COUNT(*) FROM cases WHERE substr(created_at,1,10) >= ?"
                " GROUP BY d, verdict", (dates[0],)).fetchall()
            top = self.db.execute(
                "SELECT rule, COUNT(*) c FROM findings GROUP BY rule ORDER BY c DESC, rule LIMIT 8").fetchall()
        series = {d: {"date": d, "malicious": 0, "suspicious": 0, "safe": 0, "total": 0} for d in dates}
        for d, verdict, n in per_day:
            if d in series:
                series[d][verdict.lower()] += n
                series[d]["total"] += n
        return {
            "total": sum(by_verdict.values()), "malicious": by_verdict.get("Malicious", 0),
            "suspicious": by_verdict.get("Suspicious", 0), "safe": by_verdict.get("Safe", 0),
            "open": open_count, "series": list(series.values()),
            "top_rules": [{"rule": r["rule"], "count": r["c"]} for r in top],
        }

    def iocs(self, kind=None, q=None, limit=100, offset=0):
        where, args = [], []
        if kind:
            where.append("i.kind=?")
            args.append(kind)
        if q:
            where.append("i.value LIKE ? ESCAPE '\\'")
            args.append(_like(q))
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        base = f"FROM iocs i JOIN cases c ON c.id=i.case_id {clause} GROUP BY i.kind, i.value"
        with self.lock:
            total = self.db.execute(f"SELECT COUNT(*) FROM (SELECT 1 {base})", args).fetchone()[0]
            rows = self.db.execute(
                f"SELECT i.kind kind, i.value value, COUNT(DISTINCT i.case_id) cases, MAX(c.score) max_score,"
                f" MIN(c.created_at) first_seen, MAX(c.created_at) last_seen {base}"
                f" ORDER BY cases DESC, max_score DESC, value LIMIT ? OFFSET ?", [*args, int(limit), int(offset)]
            ).fetchall()
        return [dict(r) for r in rows], total

    def open_count(self) -> int:
        with self.lock:
            return self.db.execute("SELECT COUNT(*) FROM cases WHERE status IN ('new','investigating')").fetchone()[0]

    def case_iocs(self, case_id: int):
        with self.lock:
            rows = self.db.execute("SELECT kind, value FROM iocs WHERE case_id=? ORDER BY kind, value", (case_id,)).fetchall()
        return [dict(r) for r in rows]
