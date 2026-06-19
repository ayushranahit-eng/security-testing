"""
Rendered DOM secret scanner.

Uses a live Playwright page to inspect the final browser-rendered DOM after
client-side JavaScript runs. This complements raw HTML and JavaScript-source
secret scanning.
"""

from urllib.parse import urlparse

from url_scanner.scanner.javascript_secret_scanner import (
    _dedupe_detections,
    _find_secrets_in_text,
    _first_party_pages,
    _highest_severity,
)


async def scan_rendered_dom_secrets(page, target_url: str, pages: list, cfg: dict) -> dict:
    target_host = urlparse(target_url).netloc.lower()
    max_pages = int(cfg.get("max_pages", cfg.get("max_rendered_dom_secret_pages", cfg.get("max_html_secret_pages", 20))))

    detections = []
    scanned_pages = []

    for page_url in _first_party_pages(target_host, pages)[:max_pages]:
        try:
            await page.goto(page_url, wait_until="networkidle", timeout=cfg["page_timeout"])
            rendered_html = await page.content()
        except Exception:
            continue

        scanned_pages.append(page_url)
        detections.extend(_find_secrets_in_text(rendered_html, f"rendered:{page_url}"))

    detections = _dedupe_detections(detections)

    return {
        "status": "Secrets detected in rendered DOM" if detections else "No secrets detected in rendered DOM",
        "scanned_pages": len(scanned_pages),
        "scanned_page_urls": scanned_pages,
        "detections": detections,
        "highest_severity": _highest_severity(detections) if detections else "Info",
        "note": "This pass scans the final browser-rendered DOM after client-side JavaScript runs.",
    }
