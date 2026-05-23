import re
from urllib.parse import urlparse

URL_REGEX = r"https?://[^\s<>\"']+"
IP_REGEX = r"\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
MD5_REGEX = r"\b[a-fA-F0-9]{32}\b"
SHA1_REGEX = r"\b[a-fA-F0-9]{40}\b"
SHA256_REGEX = r"\b[a-fA-F0-9]{64}\b"
DOMAIN_REGEX = r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"

COMMON_DOMAINS = {
    "gmail.com",
    "google.com",
    "microsoft.com",
    "outlook.com",
    "yahoo.com",
    "apple.com",
    "amazon.com",
}


def extract_iocs(text: str, attachment_hashes: list[str] | None = None) -> dict:
    """Extract IOCs from email body and optional attachment hashes."""
    urls = _unique(URL_REGEX, text)
    ips = _unique(IP_REGEX, text)
    md5 = _unique(MD5_REGEX, text)
    sha1 = _unique(SHA1_REGEX, text)
    sha256 = _unique(SHA256_REGEX, text)

    domains_from_urls = [_domain_from_url(u) for u in urls]
    domains_from_text = _unique(DOMAIN_REGEX, text)
    domains = _dedupe(domains_from_urls + domains_from_text)
    domains = [d for d in domains if d.lower() not in COMMON_DOMAINS]

    if attachment_hashes:
        for h in attachment_hashes:
            length = len(h)
            if length == 32 and h not in md5:
                md5.append(h)
            elif length == 40 and h not in sha1:
                sha1.append(h)
            elif length == 64 and h not in sha256:
                sha256.append(h)

    return {
        "urls": urls,
        "ips": ips,
        "domains": domains,
        "md5": md5,
        "sha1": sha1,
        "sha256": sha256,
    }


def _unique(pattern: str, text: str) -> list[str]:
    return list(dict.fromkeys(re.findall(pattern, text)))


def _dedupe(items: list[str]) -> list[str]:
    return list(dict.fromkeys(i for i in items if i))


def _domain_from_url(url: str) -> str | None:
    try:
        parsed = urlparse(url.rstrip(".,;)"))
        return parsed.hostname
    except Exception:
        return None
