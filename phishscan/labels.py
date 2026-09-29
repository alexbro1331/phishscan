"""Plain-English names for scoring rules (the raw rule ids stay in the JSON output)."""

RULE_TITLES = {
    "spf_fail": "SPF failed",
    "dkim_fail": "DKIM failed",
    "dmarc_fail": "DMARC failed",
    "no_auth_results": "No authentication results",
    "reply_to_mismatch": "Replies go to a different domain",
    "return_path_mismatch": "Bounce address on a different domain",
    "display_name_spoof": "Display name shows another address",
    "display_name_brand": "Brand name, wrong sender",
    "lookalike_domain": "Look-alike sender domain",
    "punycode_domain": "Look-alike (punycode) domain",
    "url_flagged": "Link flagged by reputation services",
    "link_text_mismatch": "Link text hides the real destination",
    "url_shortener": "Shortened link",
    "ip_literal_url": "Link points to a raw IP address",
    "ip_abuse": "Sender IP has an abuse history",
    "urgency_language": "Pressure language",
    "attachment_malicious": "Known-malicious attachment",
    "dangerous_extension": "Risky attachment type",
    "spoofed_filename": "Disguised attachment name",
}


def rule_title(rule: str) -> str:
    return RULE_TITLES.get(rule) or rule.replace("_", " ").capitalize()
