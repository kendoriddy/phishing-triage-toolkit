import time

import requests

from config import VT_API_KEY, VT_BASE_URL


class VirusTotalClient:
    """VirusTotal API v3 client for URL, IP, domain, and hash lookups."""

    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or VT_API_KEY
        self.headers = {"x-apikey": self.api_key} if self.api_key else {}
        self.enabled = bool(self.api_key)

    def check_url(self, url: str) -> dict:
        if not self.enabled:
            return {"error": "VT_API_KEY not configured", "url": url}

        try:
            submit = requests.post(
                f"{VT_BASE_URL}/urls",
                headers=self.headers,
                data={"url": url},
                timeout=30,
            )
            submit.raise_for_status()
            analysis_id = submit.json()["data"]["id"]

            from config import VT_URL_POLL_SECONDS

            time.sleep(VT_URL_POLL_SECONDS)
            return self._get_analysis(analysis_id, url)
        except requests.RequestException as exc:
            return {"error": str(exc), "url": url}

    def check_ip(self, ip: str) -> dict:
        return self._get_resource(f"ip_addresses/{ip}", ip)

    def check_domain(self, domain: str) -> dict:
        return self._get_resource(f"domains/{domain}", domain)

    def check_hash(self, file_hash: str) -> dict:
        return self._get_resource(f"files/{file_hash}", file_hash)

    def _get_resource(self, endpoint: str, indicator: str) -> dict:
        if not self.enabled:
            return {"error": "VT_API_KEY not configured", "indicator": indicator}

        try:
            response = requests.get(
                f"{VT_BASE_URL}/{endpoint}",
                headers=self.headers,
                timeout=30,
            )
            if response.status_code == 404:
                return {"indicator": indicator, "found": False}
            response.raise_for_status()
            return self._parse_stats(response.json(), indicator)
        except requests.RequestException as exc:
            return {"error": str(exc), "indicator": indicator}

    def _get_analysis(self, analysis_id: str, url: str) -> dict:
        try:
            response = requests.get(
                f"{VT_BASE_URL}/analyses/{analysis_id}",
                headers=self.headers,
                timeout=30,
            )
            response.raise_for_status()
            return self._parse_stats(response.json(), url)
        except requests.RequestException as exc:
            return {"error": str(exc), "url": url}

    def _parse_stats(self, data: dict, indicator: str) -> dict:
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", attrs.get("stats", {}))
        return {
            "indicator": indicator,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attrs.get("reputation"),
        }


def check_url(url: str) -> dict:
    return VirusTotalClient().check_url(url)


def check_all_iocs(iocs: dict, max_checks: int = 5) -> dict:
    """Check a subset of IOCs against VirusTotal to respect rate limits."""
    client = VirusTotalClient()
    results = {"urls": [], "ips": [], "domains": [], "hashes": []}

    if not client.enabled:
        return {"error": "VT_API_KEY not configured", "results": results}

    for url in iocs.get("urls", [])[:max_checks]:
        results["urls"].append(client.check_url(url))

    for ip in iocs.get("ips", [])[:max_checks]:
        results["ips"].append(client.check_ip(ip))

    for domain in iocs.get("domains", [])[:max_checks]:
        results["domains"].append(client.check_domain(domain))

    all_hashes = iocs.get("md5", []) + iocs.get("sha1", []) + iocs.get("sha256", [])
    for h in all_hashes[:max_checks]:
        results["hashes"].append(client.check_hash(h))

    return results
