"""
HTTP method analyzer.

Uses OPTIONS and TRACE to identify risky or unnecessary methods without sending
destructive state-changing requests.
"""

# Note:
# This is a protocol-surface check. It is high-signal for advertised methods
# and TRACE exposure, but it does not prove that every listed method is usable
# end-to-end on every application route.

import urllib.error
import urllib.request
from urllib.parse import urlparse


def analyze_http_methods(target_url: str, findings: list, cfg: dict) -> dict:
    origin = _origin(target_url)
    allow_methods = []
    trace_enabled = False
    trace_status = None
    observed_headers = {}

    try:
        request = urllib.request.Request(
            origin,
            method="OPTIONS",
            headers={"User-Agent": "SecurityTestingPlatform/1.0"},
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            observed_headers = dict(response.headers.items())
            allow_header = response.headers.get("Allow", "")
            allow_methods = [item.strip().upper() for item in allow_header.split(",") if item.strip()]
    except urllib.error.HTTPError as error:
        observed_headers = dict(error.headers.items()) if error.headers else {}
        allow_header = observed_headers.get("Allow", "")
        allow_methods = [item.strip().upper() for item in allow_header.split(",") if item.strip()]
    except Exception:
        pass

    try:
        request = urllib.request.Request(
            origin,
            method="TRACE",
            headers={"User-Agent": "SecurityTestingPlatform/1.0"},
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            trace_status = response.status
            trace_enabled = response.status < 400
    except urllib.error.HTTPError as error:
        trace_status = error.code
        trace_enabled = error.code not in (403, 404, 405, 501)
    except Exception:
        trace_status = None

    dangerous = [method for method in allow_methods if method in {"PUT", "DELETE", "PATCH", "TRACE"}]
    if dangerous:
        findings.append({
            "vulnerability": "HTTP Methods Enabled",
            "severity": "Medium",
            "details": [f"Server advertised methods: {', '.join(allow_methods)}"],
            "methods": allow_methods,
        })

    if trace_enabled:
        findings.append({
            "vulnerability": "HTTP TRACE Enabled",
            "severity": "Medium",
            "details": [f"TRACE request returned HTTP {trace_status} on {origin}"],
        })

    return {
        "status": "Risky methods observed" if dangerous or trace_enabled else "No risky HTTP methods observed",
        "tested_url": origin,
        "allow_methods": allow_methods,
        "dangerous_methods": dangerous,
        "trace_enabled": trace_enabled,
        "trace_status": trace_status,
        "headers_seen": observed_headers,
    }


def _origin(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"
