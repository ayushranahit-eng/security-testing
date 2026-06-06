"""
Source map exposure scanner.
"""

# Note:
# This is a source-disclosure check. It confirms whether production JavaScript
# source maps are reachable, which can expose original client-side code and
# implementation detail.

import urllib.error
import urllib.request
from html import unescape
from urllib.parse import urlparse


def scan_source_maps(target_url: str, api_calls: list, findings: list) -> dict:
    target_host = urlparse(target_url).netloc.lower()
    candidates = []
    for call in api_calls:
        raw = unescape(str(call or "").strip())
        if not raw or not raw.lower().endswith(".js"):
            continue
        parsed = urlparse(raw)
        host = parsed.netloc.lower()
        if host == target_host or host.endswith("." + target_host):
            candidates.append(raw + ".map")

    exposed = []
    for url in sorted(set(candidates))[:20]:
        if _is_accessible(url):
            exposed.append(url)

    if exposed:
        findings.append({
            "vulnerability": "JavaScript Source Maps",
            "severity": "Low",
            "details": exposed[:10],
        })

    return {
        "status": "Source maps exposed" if exposed else "No exposed source maps detected",
        "exposed_maps": exposed,
    }


def _is_accessible(url: str) -> bool:
    request = urllib.request.Request(url, headers={"User-Agent": "SecurityTestingPlatform/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status < 400
    except urllib.error.HTTPError as error:
        return False if error.code >= 400 else True
    except Exception:
        return False
