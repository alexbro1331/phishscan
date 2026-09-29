from .mitre import RULE_TO_TECHNIQUE
from .models import Finding

WEIGHTS = {
    "spf_fail": 15, "dkim_fail": 15, "dmarc_fail": 25, "no_auth_results": 10,
    "reply_to_mismatch": 15, "return_path_mismatch": 10, "display_name_spoof": 20,
    "lookalike_domain": 25, "url_flagged": 40, "ip_abuse": 20, "attachment_malicious": 50,
    "dangerous_extension": 25, "url_shortener": 10, "ip_literal_url": 15, "urgency_language": 10,
    "link_text_mismatch": 25, "punycode_domain": 20,
}
SUSPICIOUS_AT, MALICIOUS_AT = 30, 60


def finding(rule: str, reason: str) -> Finding:
    return Finding(rule, WEIGHTS[rule], reason, RULE_TO_TECHNIQUE.get(rule))
