"""
Page crawler — link discovery and element collection.
"""

import hashlib
from urllib.parse import urljoin, urlparse
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError


# ── URL helpers ────────────────────────────────────────────────────

def is_internal(base_url: str, target_url: str) -> bool:
    return urlparse(base_url).netloc == urlparse(target_url).netloc


def normalise_url(url: str) -> str:
    """Strip anchors and trailing slashes for consistent deduplication."""
    return url.split("#")[0].rstrip("/")


# ── Page state hash ────────────────────────────────────────────────

def page_state_hash(page) -> str | None:
    """
    MD5 of current URL + visible input IDs + button texts.
    Used to detect identical UI states and prevent interaction loops.
    """
    try:
        parts = [page.url]

        for el in page.locator("input:visible, textarea:visible, select:visible").all():
            try:
                parts.append(el.get_attribute("id") or el.get_attribute("name") or "")
            except Exception:
                pass

        for btn in page.locator("button").all():
            try:
                parts.append(" ".join(btn.inner_text().split())[:60])
            except Exception:
                pass

        return hashlib.md5("|".join(parts).encode()).hexdigest()
    except Exception:
        return None


# ── Link collector ─────────────────────────────────────────────────

def collect_links(page, base_url: str) -> set:
    found = set()
    try:
        for link in page.locator("a").all():
            try:
                href = link.get_attribute("href")
                if not href:
                    continue
                full_url = normalise_url(urljoin(base_url, href))
                if is_internal(base_url, full_url):
                    found.add(full_url)
            except Exception:
                pass
    except Exception:
        pass
    return found


# ── Element snapshot ───────────────────────────────────────────────

def collect_elements(page, url: str, results: dict) -> set:
    """
    Snapshot forms, inputs, textareas, buttons into results.
    Returns set of internal URLs found on the page.
    """

    # FORMS
    try:
        for idx, form in enumerate(page.locator("form").all()):
            try:
                entry = {
                    "page":    url,
                    "form_no": idx + 1,
                    "action":  form.get_attribute("action"),
                    "method":  form.get_attribute("method"),
                    "id":      form.get_attribute("id"),
                }
                if entry not in results["forms"]:
                    results["forms"].append(entry)
            except Exception:
                pass
    except Exception:
        pass

    # INPUTS
    try:
        for inp in page.locator("input").all():
            try:
                entry = {
                    "page":        url,
                    "id":          inp.get_attribute("id"),
                    "name":        inp.get_attribute("name"),
                    "type":        inp.get_attribute("type") or "text",
                    "placeholder": inp.get_attribute("placeholder"),
                    "required":    inp.get_attribute("required") is not None,
                }
                if entry not in results["inputs"]:
                    results["inputs"].append(entry)
            except Exception:
                pass
    except Exception:
        pass

    # TEXTAREAS
    try:
        for ta in page.locator("textarea").all():
            try:
                entry = {
                    "page":        url,
                    "id":          ta.get_attribute("id"),
                    "name":        ta.get_attribute("name"),
                    "type":        "textarea",
                    "placeholder": ta.get_attribute("placeholder"),
                    "required":    ta.get_attribute("required") is not None,
                }
                if entry not in results["inputs"]:
                    results["inputs"].append(entry)
            except Exception:
                pass
    except Exception:
        pass

    # BUTTONS
    try:
        for btn in page.locator("button").all():
            try:
                text = " ".join(btn.inner_text().split())
                if text and text not in results["buttons"]:
                    results["buttons"].append(text)
            except Exception:
                pass
    except Exception:
        pass

    return collect_links(page, url)


# ── Page loader ────────────────────────────────────────────────────

def load_page(page, url: str, cfg: dict):
    """Navigate to url. Returns response or None on failure."""
    try:
        return page.goto(
            url,
            wait_until="networkidle",
            timeout=cfg["page_timeout"],
        )
    except PlaywrightTimeoutError:
        print(f"   ⏱️  Timeout loading {url} — skipping")
        return None
    except Exception as e:
        print(f"   ⚠️  Error loading {url}: {e}")
        return None


def nav_back(page, url: str, cfg: dict) -> None:
    """Return to url after interaction navigated away."""
    try:
        page.goto(url, wait_until="networkidle", timeout=cfg["page_timeout"])
        page.wait_for_timeout(1_000)
    except Exception:
        pass
