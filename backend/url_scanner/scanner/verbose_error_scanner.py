"""
Verbose error scanner.

Requests likely error pages and looks for stack traces, exception names, file
paths, SQL errors, or debug output in responses.
"""

# Note:
# This is an information-leakage check. It is useful for spotting debug or
# exception detail in responses, but it does not confirm a deeper root
# vulnerability by itself.

import uuid
import urllib.error
import urllib.request


ERROR_PATTERNS = [
    "traceback (most recent call last)",
    "stack trace",
    "exception in",
    "nullreferenceexception",
    "syntax error",
    "sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "undefined index",
    "fatal error",
    "line ",
    " at ",
]


def scan_verbose_errors(target_url: str, findings: list) -> dict:
    probes = [
        f"{target_url.rstrip('/')}/__hit_scan_error_{uuid.uuid4().hex[:8]}",
        f"{target_url}?hit_error_probe=%27",
    ]
    evidence = []

    for probe in probes:
        result = _fetch_error_candidate(probe)
        if result:
            evidence.append(result)

    if evidence:
        findings.append({
            "vulnerability": "Verbose Error Messages",
            "severity": "Low",
            "details": [f"{item['url']} - HTTP {item['status']} - {item['match']}" for item in evidence],
            "error_evidence": evidence,
        })

    return {
        "status": "Verbose error leakage observed" if evidence else "No verbose error leakage observed in tested flows",
        "evidence": evidence,
    }


def _fetch_error_candidate(url: str) -> dict | None:
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "SecurityTestingPlatform/1.0"})
        with urllib.request.urlopen(request, timeout=10) as response:
            status = response.status
            body = response.read(120_000).decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as error:
        status = error.code
        body = error.read(120_000).decode("utf-8", errors="ignore")
    except Exception:
        return None

    lowered = body.lower()
    for pattern in ERROR_PATTERNS:
        if pattern in lowered:
            return {"url": url, "status": status, "match": pattern, "snippet": _snippet(body, pattern)}
    return None


def _snippet(body: str, pattern: str, width: int = 120) -> str:
    lowered = body.lower()
    idx = lowered.find(pattern)
    if idx == -1:
        return ""
    start = max(0, idx - width)
    end = min(len(body), idx + len(pattern) + width)
    return " ".join(body[start:end].split())
