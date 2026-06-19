"""
Technology fingerprinting.
"""

# Note:
# This is a heuristic reconnaissance check. It helps identify likely framework,
# CMS, server, and API indicators, but detections should be confirmed before
# making CVE or patch decisions.

from html import unescape
from urllib.parse import urlparse


def fingerprint_technology(target_url: str, page_html: str, response_headers: dict, api_calls: list) -> dict:
    headers = {str(k).lower(): str(v) for k, v in (response_headers or {}).items()}
    html = (page_html or "").lower()
    calls = [unescape(str(item or "")).lower() for item in api_calls]
    detected = []

    server_header = headers.get("server")
    powered_by = headers.get("x-powered-by")
    if server_header:
        detected.append({"category": "server", "value": server_header})
    if powered_by:
        detected.append({"category": "framework", "value": powered_by})
    if "wp-content" in html or "wordpress" in html:
        detected.append({"category": "cms", "value": "WordPress"})
    if "__next" in html or "/_next/" in html:
        detected.append({"category": "frontend", "value": "Next.js"})
    if "ng-version" in html:
        detected.append({"category": "frontend", "value": "Angular"})
    if "react" in html and "root" in html:
        detected.append({"category": "frontend", "value": "React"})
    if "vue" in html and "data-v-" in html:
        detected.append({"category": "frontend", "value": "Vue"})
    if any("/wp-json" in call for call in calls):
        detected.append({"category": "api", "value": "WordPress REST API"})
    if any("/graphql" in call for call in calls):
        detected.append({"category": "api", "value": "GraphQL"})

    deduped = []
    seen = set()
    for item in detected:
        key = (item["category"], item["value"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)

    return {
        "status": "Technology indicators detected" if deduped else "No clear technology indicators detected",
        "target_host": urlparse(target_url).netloc,
        "detected": deduped,
        "note": "Fingerprinting is heuristic and should be confirmed before CVE mapping or patch recommendations.",
    }
