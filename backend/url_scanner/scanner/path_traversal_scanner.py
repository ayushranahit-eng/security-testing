"""
Path traversal scanner.

Tests low-risk query parameters for strong file-read traversal signals.
"""

import urllib.error
import urllib.request
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


TRAVERSAL_EVIDENCE_PATTERNS = (
    "root:x:0:0:",
    "[fonts]",
    "for 16-bit app support",
    "[extensions]",
    "[mci extensions]",
)


def scan_path_traversal(target_url: str, pages: list, findings: list, cfg: dict) -> list:
    candidate_urls = _candidate_urls(target_url, pages)
    parameter_names = {name.lower() for name in cfg.get("path_traversal_parameter_names", [])}
    payloads = list(cfg.get("path_traversal_payloads", []))
    max_urls = int(cfg.get("path_traversal_max_urls", 8))
    issues = []

    for page_url in candidate_urls[:max_urls]:
        parsed = urlparse(page_url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        for index, (key, _value) in enumerate(params):
            if not _looks_traversal_relevant(key, parameter_names):
                continue
            for payload in payloads:
                mutated = list(params)
                mutated[index] = (key, payload)
                candidate_url = urlunparse(parsed._replace(query=urlencode(mutated, doseq=True)))
                status, body = _download_text(candidate_url)
                if not status or status >= 400 or not body:
                    continue
                evidence = _match_evidence(body)
                if not evidence:
                    continue
                issues.append({
                    "vector": "query_parameter",
                    "parameter": key,
                    "payload": payload,
                    "tested_url": candidate_url,
                    "status": status,
                    "evidence": evidence,
                    "severity": "High",
                    "confidence": "High",
                })
                break

    issues = _dedupe(issues)
    if issues:
        findings.append({
            "vulnerability": "Path Traversal",
            "severity": "High",
            "details": [
                f"{item['parameter']} on {item['tested_url']} returned {item['evidence']}"
                for item in issues[:12]
            ],
            "traversal_vectors": issues,
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


def _looks_traversal_relevant(name: str, configured_names: set[str]) -> bool:
    lowered = str(name or "").strip().lower()
    if lowered in configured_names:
        return True
    return any(token in lowered for token in ("file", "path", "page", "dir", "folder", "template", "doc", "download", "image"))


def _download_text(url: str) -> tuple[int | None, str | None]:
    request = urllib.request.Request(url, headers={"User-Agent": "SecurityTestingPlatform/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            body = response.read(250_000).decode("utf-8", errors="ignore")
            return response.status, body
    except urllib.error.HTTPError as error:
        try:
            body = error.read(100_000).decode("utf-8", errors="ignore")
        except Exception:
            body = None
        return error.code, body
    except Exception:
        return None, None


def _match_evidence(body: str) -> str | None:
    lowered = body.lower()
    for marker in TRAVERSAL_EVIDENCE_PATTERNS:
        if marker.lower() in lowered:
            return marker
    return None


def _dedupe(items: list) -> list:
    seen = set()
    deduped = []
    for item in items:
        key = (item["parameter"], item["tested_url"], item["evidence"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped
