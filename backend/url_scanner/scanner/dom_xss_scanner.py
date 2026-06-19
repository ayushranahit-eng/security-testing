"""
DOM-based XSS scanner.

Uses fragment-based payloads so the server never receives the payload. If the
payload appears as a real DOM node after client-side script execution, the
behavior is a strong DOM-XSS signal.
"""

import uuid
from urllib.parse import urlsplit, urlunsplit


async def scan_dom_xss(page, url: str, cfg: dict, progress=None) -> list:
    marker_prefix = cfg.get("xss_marker_prefix", "hitxss")
    payload_tag = cfg.get("dom_xss_payload_tag", "hit-dom-xss")
    token = f"{marker_prefix}-dom-{uuid.uuid4().hex[:10]}"
    payload = _build_payload(payload_tag, token)
    test_url = _with_fragment(url, payload)

    _emit(progress, "info", "dom_xss", "Testing DOM-based XSS via URL fragment", url=test_url)

    try:
        await page.goto(test_url, wait_until="networkidle", timeout=cfg["page_timeout"])
        if await _detect_payload(page, token, payload_tag):
            issue = {
                "vector": "url_fragment",
                "tested_url": test_url,
                "severity": "High",
                "confidence": "High",
                "evidence": f"Client-side code rendered fragment payload into the DOM on {test_url}",
            }
            _emit(progress, "warning", "dom_xss", "Potential DOM-based XSS detected", url=test_url)
            return [issue]
    except Exception as exc:
        _emit(progress, "warning", "dom_xss", "DOM-based XSS test skipped", url=test_url, error=str(exc))
    finally:
        await _return_to_page(page, url, cfg)

    return []


def _with_fragment(url: str, fragment: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, fragment))


def _build_payload(payload_tag: str, token: str) -> str:
    return f"<{payload_tag} data-hit-dom-xss=\"{token}\">{token}</{payload_tag}>"


async def _detect_payload(page, token: str, payload_tag: str) -> bool:
    selector = f"{payload_tag}[data-hit-dom-xss='{token}']"
    try:
        count = await page.locator(selector).count()
        if count:
            return True
    except Exception:
        pass

    try:
        return bool(await page.evaluate(
            """([needle, tag]) => {
                const html = document.documentElement.outerHTML || "";
                return html.includes(needle) && html.includes(tag);
            }""",
            [token, payload_tag],
        ))
    except Exception:
        return False


async def _return_to_page(page, url: str, cfg: dict) -> None:
    try:
        await page.goto(url, wait_until="networkidle", timeout=cfg["page_timeout"])
    except Exception:
        pass


def _emit(progress, level: str, phase: str, message: str, **data) -> None:
    if progress is None:
        return
    try:
        progress({
            "event": {
                "level": level,
                "phase": phase,
                "message": message,
                **data,
            }
        })
    except Exception:
        pass
