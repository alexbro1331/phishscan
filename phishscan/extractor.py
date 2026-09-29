import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse

_URL = re.compile(r"https?://[^\s<>\"')\]]+", re.I)
_IP = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")


@dataclass
class IOCs:
    urls: list
    domains: list
    ips: list
    hashes: list


def defang(s: str) -> str:
    return re.sub(r"^http", "hxxp", s, flags=re.I).replace(".", "[.]")


def _uniq(items):
    return list(dict.fromkeys(items))


def _is_public_ip(s: str) -> bool:
    try:
        return ipaddress.ip_address(s).is_global
    except ValueError:
        return False


def extract_iocs(email) -> IOCs:
    blob = f"{email.text}\n{email.html}"
    urls = _uniq(u.rstrip(".,;:!?") for u in _URL.findall(blob))
    domains, ips = [], []
    for u in urls:
        host = (urlparse(u).hostname or "").lower()
        if not host:
            continue
        if _IP.fullmatch(host):
            if _is_public_ip(host):
                ips.append(host)
        else:
            domains.append(host)
    for header in email.received:
        ips.extend(ip for ip in _IP.findall(header) if _is_public_ip(ip))
    hashes = [(a.filename, a.sha256) for a in email.attachments]
    return IOCs(urls, _uniq(domains), _uniq(ips), hashes)
