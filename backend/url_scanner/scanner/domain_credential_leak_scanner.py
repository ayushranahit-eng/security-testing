"""
Domain breach and credential leak checks using public XposedOrNot data.
"""

import json
import urllib.request
from urllib.parse import urlparse


def scan_domain_credential_leaks(target_url: str, findings: list) -> dict:
    domain = _best_effort_zone(urlparse(target_url).hostname)
    if not domain:
        return {"status": "No domain available", "domain": None}

    breaches = _fetch_breach_catalog()
    matches = []
    for item in breaches:
        breach_domain = str(item.get("domain", "")).lower().strip()
        if not breach_domain:
            continue
        if breach_domain == domain or breach_domain.endswith("." + domain):
            matches.append({
                "breach": item.get("breachID") or item.get("breach") or breach_domain,
                "domain": breach_domain,
                "exposed_data": item.get("exposedData", []),
                "records": item.get("exposedRecords"),
                "description": item.get("exposureDescription") or item.get("details"),
            })

    if matches:
        findings.append({
            "vulnerability": "Domain Credential Leak Check",
            "severity": "Medium",
            "details": [
                f"Public breach record matched {item['domain']} via {item['breach']}"
                for item in matches[:10]
            ],
            "breaches": matches,
        })

    return {
        "status": "Public breach records matched the domain" if matches else "No public breach catalog match found for the domain",
        "domain": domain,
        "breaches": matches,
        "provider": "XposedOrNot public breach catalog",
        "note": "This checks public breach records tied to the scanned domain, not every possible leaked employee credential on the internet.",
    }


def _fetch_breach_catalog() -> list:
    url = "https://api.xposedornot.com/v1/breaches"
    request = urllib.request.Request(url, headers={"User-Agent": "SecurityTestingPlatform/1.0", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=12) as response:
            data = json.loads(response.read().decode("utf-8", errors="ignore"))
    except Exception:
        return []

    return list(data.get("exposedBreaches", []))


def _best_effort_zone(hostname: str | None) -> str | None:
    if not hostname:
        return None
    parts = hostname.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname
