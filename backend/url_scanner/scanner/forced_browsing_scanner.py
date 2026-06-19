"""
Forced browsing scanner.
"""

# Note:
# This is a direct-route exposure check. It tests common internal-looking paths
# for reachability, but a hit does not automatically mean the route is
# sensitive without application context.

import urllib.error
import urllib.request
from urllib.parse import urlparse


def scan_forced_browsing(target_url: str, visited_pages: list, findings: list, cfg: dict) -> dict:
    parsed = urlparse(target_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    known = {str(page or "").rstrip("/") for page in visited_pages}
    hits = []

    for path in cfg.get("forced_browsing_paths", []):
        url = origin.rstrip("/") + path
        if url.rstrip("/") in known:
            continue
        status = _request_status(url)
        if status and status < 400:
            hits.append({"url": url, "status": status})

    if hits:
        findings.append({
            "vulnerability": "Forced Browsing",
            "severity": "Low",
            "details": [f"{item['url']} - HTTP {item['status']}" for item in hits[:10]],
        })

    return {
        "status": "Unlinked paths accessible" if hits else "No forced browsing hits detected",
        "hits": hits,
    }


def _request_status(url: str) -> int | None:
    request = urllib.request.Request(url, headers={"User-Agent": "SecurityTestingPlatform/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code
    except Exception:
        return None
