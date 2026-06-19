"""
HTTP response splitting scanner.

Tests whether CRLF injected into low-risk query parameters produces header
injection in the server response.
"""

import urllib.error
import urllib.request
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def scan_http_response_splitting(target_url: str, pages: list, findings: list, cfg: dict) -> list:
    parameter_names = {name.lower() for name in cfg.get("http_response_splitting_parameter_names", [])}
    candidate_urls = _candidate_urls(target_url, pages)
    issues = []

    for page_url in candidate_urls[: int(cfg.get("http_response_splitting_max_urls", 6))]:
        parsed = urlparse(page_url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        for index, (key, _value) in enumerate(params):
            if not _looks_relevant(key, parameter_names):
                continue
            injected_value = "split-test\r\nX-Hit-Header: injected"
            mutated = list(params)
            mutated[index] = (key, injected_value)
            candidate_url = urlunparse(parsed._replace(query=urlencode(mutated, doseq=True)))
            status, headers = _request_headers(candidate_url)
            if status is None or not headers:
                continue
            if "x-hit-header" in {name.lower(): value for name, value in headers.items()}:
                issues.append({
                    "parameter": key,
                    "tested_url": candidate_url,
                    "status": status,
                    "severity": "High",
                    "confidence": "High",
                    "evidence": "Injected X-Hit-Header observed in response headers",
                })

    issues = _dedupe(issues)
    if issues:
        findings.append({
            "vulnerability": "HTTP Response Splitting",
            "severity": "High",
            "details": [
                f"{item['parameter']} on {item['tested_url']} allowed header injection"
                for item in issues[:12]
            ],
            "split_vectors": issues,
        })

    return issues


def _candidate_urls(target_url: str, pages: list) -> list:
    target_host = urlparse(target_url).netloc.lower()
    seen = set()
    result = []
    for raw in [target_url, *pages]:
        url = str(raw or "").strip()
        if not url or url in seen:
            continue
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        if not parsed.query:
            continue
        if host != target_host and not host.endswith("." + target_host):
            continue
        seen.add(url)
        result.append(url)
    return result


def _looks_relevant(name: str, configured_names: set[str]) -> bool:
    lowered = str(name or "").strip().lower()
    if lowered in configured_names:
        return True
    return any(token in lowered for token in ("redirect", "return", "next", "url", "file", "download"))


def _request_headers(url: str) -> tuple[int | None, dict]:
    opener = urllib.request.build_opener(_NoRedirectHandler())
    request = urllib.request.Request(url, method="GET", headers={"User-Agent": "SecurityTestingPlatform/1.0"})
    try:
        with opener.open(request, timeout=8) as response:
            return response.status, dict(response.headers.items())
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers.items()) if error.headers else {}
    except Exception:
        return None, {}


def _dedupe(items: list) -> list:
    seen = set()
    deduped = []
    for item in items:
        key = (item["parameter"], item["tested_url"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped
