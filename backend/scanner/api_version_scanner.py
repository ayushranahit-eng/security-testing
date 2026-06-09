"""
API version exposure scanner.

Checks whether sibling API versions are publicly reachable from discovered
versioned API-like endpoints.
"""

import urllib.error
import urllib.request
from html import unescape
from urllib.parse import parse_qsl, urlparse, urlunparse, urlencode


def scan_api_versions(target_url: str, api_calls: list, findings: list, cfg: dict) -> dict:
    target_host = urlparse(target_url).netloc.lower()
    alternates = list(cfg.get("api_version_probe_candidates", []))
    max_endpoints = int(cfg.get("api_version_max_endpoints", 6))
    exposed = []
    tested = []

    for endpoint in _first_party_versioned_calls(target_host, api_calls)[:max_endpoints]:
        tested.append(endpoint)
        for candidate_url in _candidate_versions(endpoint, alternates):
            if candidate_url == endpoint:
                continue
            status = _request_status(candidate_url)
            if status is None or status >= 400:
                continue
            exposed.append({
                "tested_from": endpoint,
                "candidate_url": candidate_url,
                "status": status,
            })

    exposed = _dedupe(exposed)
    if exposed:
        findings.append({
            "vulnerability": "API Version Abuse",
            "severity": "Low",
            "details": [
                f"{item['candidate_url']} responded with HTTP {item['status']} (seeded from {item['tested_from']})"
                for item in exposed[:12]
            ],
            "versions": exposed,
        })

    return {
        "status": "Sibling API versions reachable" if exposed else "No sibling API versions confirmed",
        "tested_endpoints": tested,
        "reachable_versions": exposed,
        "note": "This is a version-parity signal. Reachable older or parallel versions should be reviewed for auth and validation consistency.",
    }


def _first_party_versioned_calls(target_host: str, api_calls: list) -> list:
    seen = set()
    result = []
    for call in api_calls:
        raw = unescape(str(call or "").strip())
        if not raw or raw in seen:
            continue
        parsed = urlparse(raw)
        host = parsed.netloc.lower()
        path = parsed.path.lower()
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if host != target_host and not host.endswith("." + target_host):
            continue
        if "/v1/" in path or "/v2/" in path or "/v3/" in path or any(key.lower() in {"version", "api-version"} for key, _ in query_pairs):
            seen.add(raw)
            result.append(raw)
    return result


def _candidate_versions(url: str, alternates: list) -> list:
    parsed = urlparse(url)
    candidates = set()

    for token in ("v1", "v2", "v3", "beta"):
        if f"/{token}/" in parsed.path.lower():
            for alternate in alternates:
                candidates.add(url.replace(f"/{token}/", f"/{alternate}/"))

    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    if query_pairs:
        for alternate in alternates:
            mutated = []
            changed = False
            for key, value in query_pairs:
                if key.lower() in {"version", "api-version"}:
                    mutated.append((key, alternate))
                    changed = True
                else:
                    mutated.append((key, value))
            if changed:
                candidates.add(urlunparse(parsed._replace(query=urlencode(mutated, doseq=True))))

    return sorted(candidates)


def _request_status(url: str) -> int | None:
    request = urllib.request.Request(url, method="GET", headers={"User-Agent": "SecurityTestingPlatform/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code
    except Exception:
        return None


def _dedupe(items: list) -> list:
    seen = set()
    deduped = []
    for item in items:
        key = (item["tested_from"], item["candidate_url"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped
