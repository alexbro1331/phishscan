from .base import BaseClient, EnrichmentResult


class URLScan(BaseClient):
    name = "urlscan"

    def check_domain(self, domain):
        # Searches existing scans only (never submits). Result shape is best-effort;
        # verify against a live response.
        def go():
            headers = {"API-Key": self.api_key} if self.api_key else {}
            data = self._get_json("https://urlscan.io/api/v1/search/", headers=headers,
                                  params={"q": f"domain:{domain}", "size": 20})
            results = data.get("results", [])
            bad = sum(1 for r in results if r.get("verdicts", {}).get("overall", {}).get("malicious"))
            return EnrichmentResult(self.name, domain, "domain", malicious=bad, total=len(results))
        return self._safe(domain, "domain", go)
