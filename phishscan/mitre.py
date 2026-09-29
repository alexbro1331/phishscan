# Technique IDs: verify against attack.mitre.org before publishing.
TECHNIQUES = {
    "T1566.001": "Phishing: Spearphishing Attachment",
    "T1566.002": "Phishing: Spearphishing Link",
    "T1036.002": "Masquerading: Right-to-Left Override",
    "T1656": "Impersonation",
    "T1672": "Email Spoofing",
}
RULE_TO_TECHNIQUE = {
    "url_flagged": "T1566.002", "link_text_mismatch": "T1566.002", "url_shortener": "T1566.002", "ip_literal_url": "T1566.002",
    "attachment_malicious": "T1566.001", "dangerous_extension": "T1566.001", "spoofed_filename": "T1036.002", "display_name_brand": "T1656",
    "display_name_spoof": "T1656", "lookalike_domain": "T1656", "punycode_domain": "T1656", "reply_to_mismatch": "T1656",
    "spf_fail": "T1672", "dkim_fail": "T1672", "dmarc_fail": "T1672", "return_path_mismatch": "T1672",
}


def techniques_for(findings) -> list[tuple[str, str]]:
    ids = []
    for f in findings:
        if f.mitre and f.mitre not in ids:
            ids.append(f.mitre)
    return [(i, TECHNIQUES[i]) for i in ids]
