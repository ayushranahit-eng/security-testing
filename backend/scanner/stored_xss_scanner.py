"""
Stored XSS scanner.

Runs a conservative persistence check against low-risk forms by submitting a
unique HTML marker, reloading the page, and checking whether the marker
persists in the DOM after the submit flow completes.
"""

import uuid


TEXT_INPUT_TYPES = {
    "text", "search", "url", "email", "tel", "number", "date",
    "datetime-local", "month", "week", "time",
}
SAFE_FORM_KEYWORDS = {
    "comment", "message", "feedback", "search", "contact", "reply",
    "review", "post", "send", "submit",
}
UNSAFE_FORM_KEYWORDS = {
    "login", "signin", "sign in", "register", "password", "checkout",
    "purchase", "pay", "delete", "remove", "unsubscribe",
}


async def scan_stored_xss(page, url: str, cfg: dict, progress=None) -> list:
    marker_prefix = cfg.get("xss_marker_prefix", "hitxss")
    payload_tag = cfg.get("stored_xss_payload_tag", "hit-stored-xss")

    try:
        forms = await page.locator("form").all()
    except Exception:
        forms = []

    issues = []
    for form_index in range(min(2, len(forms))):
        await _return_to_page(page, url, cfg)
        try:
            forms = await page.locator("form").all()
            form = forms[form_index]
        except Exception:
            continue

        metadata = await _inspect_form(form)
        if not metadata["should_test"]:
            continue

        token = f"{marker_prefix}-stored-{uuid.uuid4().hex[:10]}"
        payload = _build_payload(payload_tag, token)
        _emit(progress, "info", "stored_xss", "Testing stored XSS via low-risk form", url=url, form_action=metadata["action"])

        try:
            await _fill_form(form, payload, cfg)
            await form.evaluate("(node) => node.requestSubmit()")
            try:
                await page.wait_for_load_state("networkidle", timeout=cfg["network_idle_wait"])
            except Exception:
                pass
            await page.wait_for_timeout(cfg["post_click_wait"])

            immediate_hit = await _detect_payload(page, token, payload_tag)
            await _return_to_page(page, page.url, cfg)
            persistent_hit = await _detect_payload(page, token, payload_tag)

            if immediate_hit and persistent_hit:
                issues.append({
                    "vector": "form_submission",
                    "tested_url": page.url,
                    "severity": "High",
                    "confidence": "Medium",
                    "evidence": f"Payload persisted after form submission and page reload on {page.url}",
                })
                _emit(progress, "warning", "stored_xss", "Potential stored XSS detected", url=page.url, form_action=metadata["action"])
        except Exception as exc:
            _emit(progress, "warning", "stored_xss", "Stored XSS test skipped", url=url, form_action=metadata["action"], error=str(exc))

    await _return_to_page(page, url, cfg)
    return issues


async def _inspect_form(form) -> dict:
    method = ((await form.get_attribute("method")) or "get").strip().lower()
    action = (await form.get_attribute("action")) or "current page"
    password_fields = await form.locator("input[type='password']").count()
    file_fields = await form.locator("input[type='file']").count()

    labels = []
    for selector in ("button", "input[type='submit']"):
        try:
            elements = await form.locator(selector).all()
        except Exception:
            elements = []
        for element in elements:
            text = (await element.inner_text()).strip() if selector == "button" else ((await element.get_attribute("value")) or "").strip()
            if text:
                labels.append(text.lower())

    has_text_area = False
    try:
        textareas = await form.locator("textarea").all()
        has_text_area = bool(textareas)
    except Exception:
        pass

    has_text_input = False
    try:
        elements = await form.locator("input").all()
    except Exception:
        elements = []
    for element in elements:
        input_type = ((await element.get_attribute("type")) or "text").lower()
        if input_type in TEXT_INPUT_TYPES:
            has_text_input = True
            break

    unsafe = any(any(keyword in label for keyword in UNSAFE_FORM_KEYWORDS) for label in labels)
    safe = has_text_area or any(any(keyword in label for keyword in SAFE_FORM_KEYWORDS) for label in labels)

    return {
        "method": method.upper(),
        "action": action,
        "should_test": bool((has_text_area or has_text_input) and safe and not unsafe and not password_fields and not file_fields),
    }


async def _fill_form(form, payload: str, cfg: dict) -> None:
    values = cfg.get("test_values", {})
    payload_used = False
    fields = await form.locator("input, textarea, select").all()

    for field in fields:
        tag_name = await field.evaluate("(node) => node.tagName.toLowerCase()")
        input_type = ((await field.get_attribute("type")) or "text").lower()

        if tag_name == "select":
            options = await field.locator("option").all()
            for option in options:
                value = ((await option.get_attribute("value")) or "").strip()
                if value:
                    await field.select_option(value)
                    break
            continue

        if input_type in {"hidden", "button", "submit", "reset", "image", "file", "password"}:
            continue
        if input_type == "checkbox":
            if not await field.is_checked():
                await field.check()
            continue
        if input_type == "radio":
            try:
                await field.check()
            except Exception:
                pass
            continue

        if tag_name == "textarea" and not payload_used:
            await field.fill(payload)
            payload_used = True
            continue

        if input_type in TEXT_INPUT_TYPES and not payload_used:
            await field.fill(payload)
            payload_used = True
            continue

        await field.fill(str(values.get(input_type) or values.get("text", "test")))


def _build_payload(payload_tag: str, token: str) -> str:
    return f"<{payload_tag} data-hit-stored-xss=\"{token}\">{token}</{payload_tag}>"


async def _detect_payload(page, token: str, payload_tag: str) -> bool:
    selector = f"{payload_tag}[data-hit-stored-xss='{token}']"
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
