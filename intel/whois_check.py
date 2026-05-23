"""WHOIS domain age checks — newly registered domains are high-risk."""

from datetime import datetime, timezone

from config import DOMAIN_AGE_SUSPICIOUS_DAYS, DOMAIN_AGE_CRITICAL_DAYS

try:
    import whois
except ImportError:
    whois = None


def check_domain(domain: str) -> dict:
    """Look up domain registration date and compute age."""
    if whois is None:
        return {"domain": domain, "error": "python-whois not installed"}

    try:
        record = whois.whois(domain)
        creation = record.creation_date
        if isinstance(creation, list):
            creation = creation[0]

        if creation is None and _is_unregistered(record):
            return {
                "domain": domain,
                "creation_date": None,
                "age_days": None,
                "registrar": None,
                "suspicious": True,
                "critical": True,
                "unregistered": True,
                "risk_note": "Domain not registered — likely phishing or typosquat",
            }

        age_days = None
        if creation:
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            age_days = (now - creation).days

        suspicious = age_days is not None and age_days < DOMAIN_AGE_SUSPICIOUS_DAYS
        critical = age_days is not None and age_days < DOMAIN_AGE_CRITICAL_DAYS

        return {
            "domain": domain,
            "creation_date": creation.isoformat() if creation else None,
            "age_days": age_days,
            "registrar": _normalize(record.registrar),
            "suspicious": suspicious or age_days is None,
            "critical": critical,
            "risk_note": _risk_note(age_days),
        }
    except Exception as exc:
        msg = str(exc)
        if "No match" in msg or "NOT FOUND" in msg.upper():
            return {
                "domain": domain,
                "creation_date": None,
                "age_days": None,
                "registrar": None,
                "suspicious": True,
                "critical": True,
                "unregistered": True,
                "risk_note": "Domain not registered — likely phishing",
            }
        return {"domain": domain, "error": _short_error(msg)}


def _is_unregistered(record) -> bool:
    text = str(record).upper()
    return "NO MATCH" in text or "NOT FOUND" in text


def _short_error(msg: str) -> str:
    first_line = msg.strip().split("\n")[0]
    return first_line[:120]


def check_all_domains(iocs: dict, max_checks: int = 5) -> dict:
    """Check extracted domains against WHOIS."""
    results = []
    for domain in iocs.get("domains", [])[:max_checks]:
        results.append(check_domain(domain))
    return {"domains": results}


def _normalize(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        return value[0] if value else None
    return str(value)


def _risk_note(age_days: int | None) -> str:
    if age_days is None:
        return "Registration date unknown"
    if age_days < DOMAIN_AGE_CRITICAL_DAYS:
        return f"Very new domain ({age_days} days) — high phishing risk"
    if age_days < DOMAIN_AGE_SUSPICIOUS_DAYS:
        return f"Recently registered ({age_days} days) — suspicious"
    if age_days < 365:
        return f"Domain is {age_days} days old — moderate trust"
    return f"Established domain ({age_days} days)"
