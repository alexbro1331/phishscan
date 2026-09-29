from .base import BaseClient, EnrichmentResult


class AbuseIPDB(BaseClient):
    name = "abuseipdb"

    def check_ip(self, ip):
        def go():
            data = self._get_json("https://api.abuseipdb.com/api/v2/check",
                                  headers={"Key": self.api_key, "Accept": "application/json"},
                                  params={"ipAddress": ip, "maxAgeInDays": 90})
            return EnrichmentResult(self.name, ip, "ip",
                                    score=data.get("data", {}).get("abuseConfidenceScore", 0))
        return self._safe(ip, "ip", go)
