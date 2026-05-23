def calculate_score(
    iocs: dict,
    vt_data: dict | None = None,
    auth_results: dict | None = None,
    talos_data: dict | None = None,
    whois_data: dict | None = None,
    yara_data: dict | None = None,
) -> int:
    """Calculate composite risk score from IOCs and threat intel signals."""
    score = 0

    score += len(iocs.get("urls", [])) * 10
    score += len(iocs.get("ips", [])) * 5
    score += len(iocs.get("domains", [])) * 3
    score += len(iocs.get("md5", [])) * 8
    score += len(iocs.get("sha1", [])) * 8
    score += len(iocs.get("sha256", [])) * 8

    vt_data = vt_data or {}
    for category in ("urls", "ips", "domains", "hashes"):
        for result in vt_data.get(category, []):
            if result.get("malicious", 0) > 0:
                score += 50
            if result.get("suspicious", 0) > 0:
                score += 25

    auth_results = auth_results or {}
    if auth_results.get("spf") == "fail":
        score += 15
    if auth_results.get("dkim") == "fail":
        score += 15
    if auth_results.get("dmarc") == "fail":
        score += 20

    talos_data = talos_data or {}
    for category in ("ips", "domains"):
        for result in talos_data.get(category, []):
            rep = (result.get("reputation") or "").lower()
            if "poor" in rep or "bad" in rep or "untrustworthy" in rep:
                score += 20
            elif "neutral" in rep or "questionable" in rep:
                score += 10

    whois_data = whois_data or {}
    for result in whois_data.get("domains", []):
        if result.get("unregistered"):
            score += 15
        elif result.get("critical"):
            score += 20
        elif result.get("suspicious"):
            score += 10

    yara_data = yara_data or {}
    severity_points = {"critical": 20, "high": 15, "medium": 10, "low": 5}
    yara_bonus = 0
    for match in yara_data.get("matches", []):
        yara_bonus += severity_points.get(match.get("severity", "medium"), 10)
    score += min(yara_bonus, 35)

    return min(score, 100)


def classify(score: int) -> str:
    """Map numeric score to phishing verdict."""
    if score >= 80:
        return "Critical phishing"
    if score >= 50:
        return "High-risk suspicious"
    if score >= 20:
        return "Needs review"
    return "Likely safe"


def risk_level(score: int) -> str:
    """Return human-readable risk level label."""
    if score >= 81:
        return "Critical"
    if score >= 51:
        return "High"
    if score >= 21:
        return "Medium"
    return "Low"
