import base64

from .base import BaseClient, EnrichmentResult

BASE = "https://www.virustotal.com/api/v3"


class VirusTotal(BaseClient):
    name = "virustotal"

    def _lookup(self, indicator, kind, path):
        def go():
            data = self._get_json(f"{BASE}/{path}", headers={"x-apikey": self.api_key})
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return EnrichmentResult(self.name, indicator, kind, malicious=stats.get("malicious", 0),
                                    total=sum(stats.values()))
        return self._safe(indicator, kind, go)

    def check_url(self, url):
        uid = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        return self._lookup(url, "url", f"urls/{uid}")

    def check_hash(self, sha256):
        return self._lookup(sha256, "hash", f"files/{sha256}")

    def check_ip(self, ip):
        return self._lookup(ip, "ip", f"ip_addresses/{ip}")
