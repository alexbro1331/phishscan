import json
import sqlite3
import threading
import time
from collections import deque


class Cache:
    def __init__(self, path=":memory:", ttl=86400, clock=time.time):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.lock = threading.Lock()
        self.db.execute("CREATE TABLE IF NOT EXISTS c (key TEXT PRIMARY KEY, value TEXT, ts REAL)")
        self.ttl, self.clock = ttl, clock

    def get(self, key):
        with self.lock:
            row = self.db.execute("SELECT value, ts FROM c WHERE key=?", (key,)).fetchone()
        if row and self.clock() - row[1] < self.ttl:
            return json.loads(row[0])
        return None

    def set(self, key, value):
        with self.lock:
            self.db.execute("INSERT OR REPLACE INTO c VALUES (?,?,?)", (key, json.dumps(value), self.clock()))
            self.db.commit()


class RateLimiter:
    def __init__(self, max_calls, period, clock=time.monotonic, sleep=time.sleep):
        self.max, self.period, self.clock, self.sleep = max_calls, period, clock, sleep
        self.calls = deque()
        self.lock = threading.Lock()

    def wait(self):
        with self.lock:
            self._wait()

    def _wait(self):
        while True:
            now = self.clock()
            while self.calls and now - self.calls[0] >= self.period:
                self.calls.popleft()
            if len(self.calls) < self.max:
                break
            self.sleep(self.period - (now - self.calls[0]))
        self.calls.append(self.clock())
