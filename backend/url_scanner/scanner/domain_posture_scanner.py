"""
Domain posture scanner.

Collects best-effort public registration-age and parking signals.
"""

import json
from datetime import datetime, timezone
from urllib.parse import urlparse
import urllib.request


PARKING_MARKERS = (
    "buy this domain",
    "domain is for sale",
    "this domain may be for sale",
    "parked free",
    "parkingcrew",
    "sedo",
    "hugedomains",
    "godaddy",
    "coming soon",
)


def scan_domain_posture(target_url: str, initial_html: str, findings: list, cfg: dict) -> dict:
    hostname = urlparse(target_url).hostname
    domain = _best_effort_zone(hostname)
    if not domain:
        return {"status": "No domain available", "domain": None}

    parking_detected = _looks_parked(initial_html)
    rdap_data = _fetch_rdap(domain)
    registration_date = _registration_date(rdap_data)
    age_days = None
    if registration_date:
        age_days = max(0, int((datetime.now(timezone.utc) - registration_date).total_seconds() // 86400))

    threshold_days = int(cfg.get("new_domain_age_threshold_days", 30))
    if parking_detected or (age_days is not None and age_days <= threshold_days):
        finding_details = []
        if parking_detected:
            finding_details.append(f"Parking markers detected in the homepage content for {domain}")
        if age_days is not None and age_days <= threshold_days:
            finding_details.append(f"Domain registration appears recent: about {age_days} day(s) old")
        findings.append({
            "vulnerability": "Domain Age & Parking Detection",
            "severity": "Low",
            "details": finding_details,
            "domain": domain,
            "age_days": age_days,
            "parking_detected": parking_detected,
        })

    return {
        "status": "Parking or newly registered domain signals detected" if parking_detected or (age_days is not None and age_days <= threshold_days) else "No parking or very-new-domain signal detected",
        "domain": domain,
        "registration_date": registration_date.isoformat() if registration_date else None,
        "age_days": age_days,
        "parking_detected": parking_detected,
        "note": "Registration age is a best-effort passive signal from RDAP. Parking detection is content-heuristic based.",
    }


def _best_effort_zone(hostname: str | None) -> str | None:
    if not hostname:
        return None
    parts = hostname.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname


def _looks_parked(html: str) -> bool:
    lowered = str(html or "").lower()
    return any(marker in lowered for marker in PARKING_MARKERS)


def _fetch_rdap(domain: str) -> dict:
    url = f"https://rdap.org/domain/{domain}"
    request = urllib.request.Request(url, headers={"User-Agent": "SecurityTestingPlatform/1.0", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.loads(response.read().decode("utf-8", errors="ignore"))
    except Exception:
        return {}


def _registration_date(rdap_data: dict) -> datetime | None:
    for event in rdap_data.get("events", []):
        action = str(event.get("eventAction", "")).lower()
        if action not in {"registration", "registered"}:
            continue
        raw = event.get("eventDate")
        parsed = _parse_rfc3339(raw)
        if parsed is not None:
            return parsed
    return None


def _parse_rfc3339(raw: str | None) -> datetime | None:
    if not raw:
        return None
    text = str(raw).strip()
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return datetime.fromisoformat(text).astimezone(timezone.utc)
    except Exception:
        return None
