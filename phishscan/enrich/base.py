from dataclasses import dataclass

import requests


class EnrichmentError(Exception):
    pass


@dataclass
class EnrichmentResult:
    source: str
    indicator: str
    kind: str
    malicious: int = 0
    total: int = 0
    score: int | None = None
    error: str | None = None


class BaseClient:
    name = ""

    def __init__(self, api_key=None, session=None, cache=None, limiter=None, timeout=10):
        self.api_key = api_key
        self.session = session or requests.Session()
        self.cache, self.limiter, self.timeout = cache, limiter, timeout

    def _get_json(self, url, headers=None, params=None):
        key = f"{self.name}|{url}|{sorted((params or {}).items())}"
        if self.cache is not None:
            hit = self.cache.get(key)
            if hit is not None:
                return hit
        if self.limiter:
            self.limiter.wait()
        try:
            resp = self.session.get(url, headers=headers, params=params, timeout=self.timeout)
        except requests.RequestException as exc:
            raise EnrichmentError(f"{self.name}: network error") from exc
        code = resp.status_code
        if code == 404:
            data = {}
        elif code == 429:
            raise EnrichmentError(f"{self.name}: rate limited")
        elif code in (401, 403):
            raise EnrichmentError(f"{self.name}: invalid API key")
        elif code >= 400:
            raise EnrichmentError(f"{self.name}: HTTP {code}")
        else:
            try:
                data = resp.json()
            except ValueError as exc:
                raise EnrichmentError(f"{self.name}: bad response") from exc
        if self.cache is not None:
            self.cache.set(key, data)
        return data

    def _safe(self, indicator, kind, fn):
        try:
            return fn()
        except EnrichmentError as exc:
            return EnrichmentResult(self.name, indicator, kind, error=str(exc))
