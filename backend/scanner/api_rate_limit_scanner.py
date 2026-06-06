"""
API rate-limit scanner.
"""

# Note:
# This is a lightweight abuse-resistance check. It looks for obvious lack of
# throttling on a discovered API-like endpoint, but it is not a complete brute
# force or distributed rate-limit evaluation.

import time
import urllib.error
import urllib.request
from html import unescape
from urllib.parse import urlparse


def scan_api_rate_limits(target_url: str, api_calls: list, findings: list, cfg: dict) -> dict:
    endpoint = _pick_first_party_api(target_url, api_calls)
    if not endpoint:
        return {"status": "No API-like endpoint available for rate-limit probing", "tested_endpoint": None}

    attempts = int(cfg.get("rate_limit_probe_requests", 6))
    delay_ms = int(cfg.get("rate_limit_probe_delay_ms", 250))
    statuses = []
    throttled = False

    for _ in range(attempts):
        status, headers = _request_once(endpoint)
        statuses.append(status)
        if status == 429 or "retry-after" in {str(k).lower(): str(v) for k, v in headers.items()}:
            throttled = True
            break
        time.sleep(delay_ms / 1000)

    if not throttled and all(status and status < 500 for status in statuses if status is not None):
        findings.append({
            "vulnerability": "API Rate Limiting Absent",
            "severity": "Low",
            "details": [f"{endpoint} handled {len(statuses)} quick request(s) without throttling: {statuses}"],
        })

    return {
        "status": "No throttling observed" if not throttled else "Rate limiting observed",
        "tested_endpoint": endpoint,
        "statuses": statuses,
        "throttled": throttled,
    }


def _pick_first_party_api(target_url: str, api_calls: list) -> str | None:
    target_host = urlparse(target_url).netloc.lower()
    for call in api_calls:
        raw = unescape(str(call or "").strip())
        if not raw:
            continue
        parsed = urlparse(raw)
        if parsed.netloc.lower() not in {target_host} and not parsed.netloc.lower().endswith("." + target_host):
            continue
        path = parsed.path.lower()
        if any(token in path for token in ("/api/", "/graphql", "/v1/", "/v2/")):
            return raw
    return None


def _request_once(url: str) -> tuple[int | None, dict]:
    request = urllib.request.Request(url, method="GET", headers={"User-Agent": "SecurityTestingPlatform/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, dict(response.headers.items())
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers.items()) if error.headers else {}
    except Exception:
        return None, {}
