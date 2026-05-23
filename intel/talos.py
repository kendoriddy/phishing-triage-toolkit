import re

import requests

from config import TALOS_LOOKUP_URL


def check_ip(ip: str) -> dict:
    """Look up IP reputation via Cisco Talos reputation center."""
    url = f"{TALOS_LOOKUP_URL}?search={ip}"
    try:
        response = requests.get(url, timeout=30, headers={"User-Agent": "PhishingTriageToolkit/1.0"})
        response.raise_for_status()
        return _parse_reputation(response.text, ip, "ip")
    except requests.RequestException as exc:
        return {"indicator": ip, "type": "ip", "error": str(exc)}


def check_domain(domain: str) -> dict:
    """Look up domain reputation via Cisco Talos reputation center."""
    url = f"{TALOS_LOOKUP_URL}?search={domain}"
    try:
        response = requests.get(url, timeout=30, headers={"User-Agent": "PhishingTriageToolkit/1.0"})
        response.raise_for_status()
        return _parse_reputation(response.text, domain, "domain")
    except requests.RequestException as exc:
        return {"indicator": domain, "type": "domain", "error": str(exc)}


def check_all_iocs(iocs: dict, max_checks: int = 5) -> dict:
    """Check IPs and domains against Talos."""
    results = {"ips": [], "domains": []}

    for ip in iocs.get("ips", [])[:max_checks]:
        results["ips"].append(check_ip(ip))

    for domain in iocs.get("domains", [])[:max_checks]:
        results["domains"].append(check_domain(domain))

    return results


def _parse_reputation(html: str, indicator: str, indicator_type: str) -> dict:
    """Extract reputation category from Talos HTML response."""
    reputation = "Unknown"
    patterns = [
        r"Email Reputation[^<]*<[^>]*>([^<]+)",
        r"Web Reputation[^<]*<[^>]*>([^<]+)",
        r'"reputation"\s*:\s*"([^"]+)"',
        r"Reputation:\s*([^<\n]+)",
    ]

    for pattern in patterns:
        match = re.search(pattern, html, re.I)
        if match:
            reputation = match.group(1).strip()
            break

    web_score = None
    score_match = re.search(r"Web Score[^0-9]*(\d+)", html, re.I)
    if score_match:
        web_score = int(score_match.group(1))

    return {
        "indicator": indicator,
        "type": indicator_type,
        "reputation": reputation,
        "web_score": web_score,
    }
