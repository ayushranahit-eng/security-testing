"""
HTML secret scanner.

Scans raw HTML responses for exposed keys, tokens, and high-entropy secrets.
"""

from urllib.parse import urlparse

from scanner.javascript_secret_scanner import (
    _dedupe_detections,
    _download_text,
    _find_secrets_in_text,
    _first_party_pages,
    _highest_severity,
)


def scan_html_secrets(target_url: str, pages: list, initial_html: str, findings: list, cfg: dict) -> dict:
    target_host = urlparse(target_url).netloc.lower()
    max_pages = int(cfg.get("max_html_secret_pages", 10))
    max_bytes = int(cfg.get("max_download_bytes_per_file", 500_000))

    detections = []
    scanned_pages = []

    if initial_html:
        detections.extend(_find_secrets_in_text(initial_html, f"html:{target_url}"))
        scanned_pages.append(target_url)

    for page_url in _first_party_pages(target_host, pages):
        if page_url == target_url or len(scanned_pages) >= max_pages:
            continue
        html = _download_text(page_url, max_bytes)
        if html is None:
            continue
        scanned_pages.append(page_url)
        detections.extend(_find_secrets_in_text(html, f"html:{page_url}"))

    detections = _dedupe_detections(detections)

    if detections:
        findings.append({
            "vulnerability": "Hardcoded Secrets in HTML",
            "severity": _highest_severity(detections),
            "details": [
                f"{item['type']} in {item['source']} ({item['confidence']} confidence)"
                for item in detections[:12]
            ],
            "secrets": detections,
        })

    return {
        "status": "Secrets detected in HTML" if detections else "No secrets detected in HTML",
        "scanned_pages": len(scanned_pages),
        "detections": detections,
        "note": "This complements JavaScript secret scanning by checking rendered HTML, inline JSON, meta tags, and template output.",
    }
