"""
Reflected XSS scanner.

Uses low-risk payloads to check whether query parameters or safe form flows
reflect HTML back into the DOM without sanitization.
"""

import uuid
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


TEXT_INPUT_TYPES = {
    "text", "search", "url", "email", "tel", "number", "password",
    "date", "datetime-local", "month", "week", "time",
}
SAFE_SUBMIT_KEYWORDS = {"search", "find", "lookup", "filter", "query", "check"}


async def scan_reflected_xss(page, url: str, cfg: dict, progress=None) -> list:
    issues = []
    marker_prefix = cfg.get("xss_marker_prefix", "hitxss")
    payload_tag = cfg.get("xss_payload_tag", "hit-xss-check")

    issues.extend(await _scan_query_parameters(page, url, marker_prefix, payload_tag, cfg, progress))
    issues.extend(await _scan_safe_forms(page, url, marker_prefix, payload_tag, cfg, progress))
    return issues


async def _scan_query_parameters(page, url: str, marker_prefix: str, payload_tag: str, cfg: dict, progress=None) -> list:
    parsed = urlparse(url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    if not params:
        return []

    issues = []
    max_params = min(3, len(params))
    for index in range(max_params):
        token = f"{marker_prefix}-{uuid.uuid4().hex[:10]}"
        payload = _build_payload(payload_tag, token)
        mutated = list(params)
        mutated[index] = (mutated[index][0], payload)
        test_url = urlunparse(parsed._replace(query=urlencode(mutated, doseq=True)))

        _emit(progress, "info", "xss", "Testing reflected XSS via query parameter", url=test_url, parameter=mutated[index][0])

        try:
            await page.goto(test_url, wait_until="networkidle", timeout=cfg["page_timeout"])
            hit = await _detect_payload_reflection(page, token, payload_tag)
            if hit:
                issues.append({
                    "vector": "url_parameter",
                    "parameter": mutated[index][0],
                    "tested_url": test_url,
                    "severity": "High",
                    "confidence": "High",
                    "evidence": f"Unsanitized HTML payload reflected for parameter '{mutated[index][0]}' on {test_url}",
                })
                _emit(progress, "warning", "xss", "Potential reflected XSS detected", url=test_url, parameter=mutated[index][0])
        except Exception as exc:
            _emit(progress, "warning", "xss", "XSS query-parameter test skipped", url=test_url, error=str(exc))
        finally:
            await _return_to_page(page, url, cfg)

    return issues


async def _scan_safe_forms(page, url: str, marker_prefix: str, payload_tag: str, cfg: dict, progress=None) -> list:
    issues = []
    try:
        forms = await page.locator("form").all()
    except Exception:
        forms = []

    max_forms = min(3, len(forms))
    for form_index in range(max_forms):
        await _return_to_page(page, url, cfg)
        try:
            forms = await page.locator("form").all()
            form = forms[form_index]
        except Exception:
            continue

        metadata = await _inspect_form(form)
        if not metadata["should_test"]:
            continue

        token = f"{marker_prefix}-{uuid.uuid4().hex[:10]}"
        payload = _build_payload(payload_tag, token)
        _emit(progress, "info", "xss", "Testing reflected XSS via safe form", url=url, form_action=metadata["action"], form_method=metadata["method"])

        try:
            await _fill_form_for_xss(form, payload, cfg)
            await form.evaluate("(node) => node.requestSubmit()")
            try:
                await page.wait_for_load_state("networkidle", timeout=cfg["network_idle_wait"])
            except Exception:
                pass
            await page.wait_for_timeout(cfg["post_click_wait"])

            hit = await _detect_payload_reflection(page, token, payload_tag)
            if hit:
                issues.append({
                    "vector": "form_submission",
                    "parameter": metadata["method"],
                    "tested_url": page.url,
                    "severity": "High",
                    "confidence": "Medium",
                    "evidence": f"Unsanitized HTML payload reflected after submitting a safe {metadata['method']} form on {url}",
                })
                _emit(progress, "warning", "xss", "Potential reflected XSS detected after form submission", url=page.url, form_action=metadata["action"])
        except Exception as exc:
            _emit(progress, "warning", "xss", "XSS form test skipped", url=url, form_action=metadata["action"], error=str(exc))

    await _return_to_page(page, url, cfg)
    return issues


async def _inspect_form(form) -> dict:
    method = ((await form.get_attribute("method")) or "get").strip().lower()
    action = (await form.get_attribute("action")) or ""

    password_fields = await form.locator("input[type='password']").count()
    file_fields = await form.locator("input[type='file']").count()
    text_inputs = await form.locator("input, textarea").all()
    has_text_input = False
    for field in text_inputs:
        input_type = ((await field.get_attribute("type")) or "text").lower()
        if input_type in TEXT_INPUT_TYPES or await field.evaluate("(node) => node.tagName.toLowerCase() === 'textarea'"):
            has_text_input = True
            break

    submit_labels = []
    for selector in ("button", "input[type='submit']"):
        try:
            elements = await form.locator(selector).all()
        except Exception:
            elements = []
        for element in elements:
            text = (await element.inner_text()).strip() if selector == "button" else ((await element.get_attribute("value")) or "").strip()
            if text:
                submit_labels.append(text.lower())

    safe_submit = (
        method == "get"
        or any(any(keyword in label for keyword in SAFE_SUBMIT_KEYWORDS) for label in submit_labels)
    )

    should_test = bool(has_text_input and safe_submit and not password_fields and not file_fields)
    return {
        "method": method.upper(),
        "action": action or "current page",
        "should_test": should_test,
    }


async def _fill_form_for_xss(form, payload: str, cfg: dict) -> None:
    values = cfg.get("test_values", {})

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

        value = payload if (tag_name == "textarea" or input_type in TEXT_INPUT_TYPES) else values.get(input_type) or values.get("text", "test")
        await field.fill(str(value))


async def _detect_payload_reflection(page, token: str, payload_tag: str) -> bool:
    selector = f"{payload_tag}[data-hit-xss='{token}']"
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


def _build_payload(payload_tag: str, token: str) -> str:
    return f"<{payload_tag} data-hit-xss=\"{token}\">{token}</{payload_tag}>"


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
