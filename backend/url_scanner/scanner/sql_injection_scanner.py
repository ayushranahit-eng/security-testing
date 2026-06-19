"""
SQL injection scanner.

Performs conservative GET-based tests for SQL error leakage and strong response
anomalies on existing query parameters and low-risk search-style forms.
"""

import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


TEXT_INPUT_TYPES = {
    "text", "search", "url", "email", "tel", "number", "password",
    "date", "datetime-local", "month", "week", "time",
}
SAFE_SUBMIT_KEYWORDS = {"search", "find", "lookup", "filter", "query", "check"}


async def scan_sql_injection(page, url: str, cfg: dict, progress=None) -> list:
    baseline = await _capture_baseline(page, url, cfg)
    if baseline is None:
        return []

    issues = []
    issues.extend(await _scan_query_parameters(page, url, cfg, baseline, progress))
    issues.extend(await _scan_get_forms(page, url, cfg, progress))
    await _return_to_page(page, url, cfg)
    return _dedupe(issues)


async def _capture_baseline(page, url: str, cfg: dict) -> dict | None:
    try:
        await page.goto(url, wait_until="networkidle", timeout=cfg["page_timeout"])
        body = await page.content()
        return {
            "status": 200,
            "body": body,
            "length": len(body),
            "title": await page.title(),
        }
    except Exception:
        return None


async def _scan_query_parameters(page, url: str, cfg: dict, baseline: dict, progress=None) -> list:
    parsed = urlparse(url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    if not params:
        return []

    issues = []
    payloads = cfg.get("sqli_test_payloads", ["'"])
    max_params = int(cfg.get("sqli_max_test_parameters", 3))

    for index, (key, value) in enumerate(params[:max_params]):
        for payload in payloads:
            mutated = list(params)
            mutated[index] = (key, f"{value}{payload}")
            candidate_url = urlunparse(parsed._replace(query=urlencode(mutated, doseq=True)))

            _emit(progress, "info", "sqli", "Testing SQL injection parameter", url=candidate_url, parameter=key)
            evidence = await _evaluate_candidate(page, candidate_url, cfg, baseline)
            if evidence:
                issues.append({
                    "vector": "url_parameter",
                    "parameter": key,
                    "tested_url": candidate_url,
                    "severity": evidence["severity"],
                    "confidence": evidence["confidence"],
                    "evidence": evidence["message"],
                })
                _emit(progress, "warning", "sqli", "Potential SQL injection detected", url=candidate_url, parameter=key)
                break

        await _return_to_page(page, url, cfg)

    return issues


async def _scan_get_forms(page, url: str, cfg: dict, progress=None) -> list:
    issues = []
    payload = (cfg.get("sqli_test_payloads") or ["'"])[0]

    try:
        forms = await page.locator("form").all()
    except Exception:
        forms = []

    for form_index in range(min(3, len(forms))):
        await _return_to_page(page, url, cfg)
        try:
            forms = await page.locator("form").all()
            form = forms[form_index]
        except Exception:
            continue

        metadata = await _inspect_form(form)
        if not metadata["should_test"]:
            continue

        _emit(progress, "info", "sqli", "Testing SQL injection via safe form", url=url, form_method=metadata["method"])
        try:
            await _fill_form_for_sqli(form, cfg, payload)
            await form.evaluate("(node) => node.requestSubmit()")
            try:
                await page.wait_for_load_state("networkidle", timeout=cfg["network_idle_wait"])
            except Exception:
                pass
            await page.wait_for_timeout(cfg["post_click_wait"])

            body = await page.content()
            evidence = _inspect_response(body, len(body), cfg)
            if evidence:
                issues.append({
                    "vector": "form_submission",
                    "parameter": metadata["method"],
                    "tested_url": page.url,
                    "severity": evidence["severity"],
                    "confidence": evidence["confidence"],
                    "evidence": evidence["message"],
                })
                _emit(progress, "warning", "sqli", "Potential SQL injection detected", url=page.url, form_method=metadata["method"])
        except Exception as exc:
            _emit(progress, "warning", "sqli", "SQL injection form test skipped", url=url, error=str(exc))

    return issues


async def _evaluate_candidate(page, candidate_url: str, cfg: dict, baseline: dict) -> dict | None:
    try:
        await page.goto(candidate_url, wait_until="networkidle", timeout=cfg["page_timeout"])
        body = await page.content()
        length = len(body)
        return _inspect_response(body, length, cfg, baseline)
    except Exception as exc:
        text = str(exc).lower()
        if any(token in text for token in ("500", "sql", "database", "syntax")):
            return {
                "severity": "High",
                "confidence": "Medium",
                "message": f"Navigation error after SQL payload: {exc}",
            }
        return None


def _inspect_response(body: str, length: int, cfg: dict, baseline: dict | None = None) -> dict | None:
    lowered = body.lower()
    for pattern in cfg.get("sqli_error_patterns", []):
        if pattern.lower() in lowered:
            return {
                "severity": "High",
                "confidence": "High",
                "message": f"Database error pattern detected: {pattern}",
            }

    if baseline:
        baseline_length = baseline.get("length", 0)
        if baseline_length and abs(length - baseline_length) > max(1200, baseline_length * 0.45):
            return {
                "severity": "Medium",
                "confidence": "Low",
                "message": f"Strong response-length anomaly after SQL payload ({baseline_length} -> {length} bytes)",
            }

    if re.search(r"(sql|database).{0,40}(error|exception)", lowered):
        return {
            "severity": "High",
            "confidence": "Medium",
            "message": "Response content suggests a backend SQL or database exception",
        }

    return None


async def _inspect_form(form) -> dict:
    method = ((await form.get_attribute("method")) or "get").strip().lower()
    if method != "get":
        return {"method": method.upper(), "should_test": False}

    password_fields = await form.locator("input[type='password']").count()
    file_fields = await form.locator("input[type='file']").count()
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

    has_text_input = False
    try:
        elements = await form.locator("input, textarea").all()
    except Exception:
        elements = []
    for element in elements:
        input_type = ((await element.get_attribute("type")) or "text").lower()
        if input_type in TEXT_INPUT_TYPES or await element.evaluate("(node) => node.tagName.toLowerCase() === 'textarea'"):
            has_text_input = True
            break

    safe_submit = any(any(keyword in label for keyword in SAFE_SUBMIT_KEYWORDS) for label in submit_labels)
    return {
        "method": method.upper(),
        "should_test": bool(has_text_input and safe_submit and not password_fields and not file_fields),
    }


async def _fill_form_for_sqli(form, cfg: dict, payload: str) -> None:
    values = cfg.get("test_values", {})
    filled = False

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

        if not filled and (tag_name == "textarea" or input_type in TEXT_INPUT_TYPES):
            await field.fill(f"test{payload}")
            filled = True
        else:
            await field.fill(str(values.get(input_type) or values.get("text", "test")))


async def _return_to_page(page, url: str, cfg: dict) -> None:
    try:
        await page.goto(url, wait_until="networkidle", timeout=cfg["page_timeout"])
    except Exception:
        pass


def _dedupe(items: list) -> list:
    seen = set()
    unique = []
    for item in items:
        key = (item["vector"], item["parameter"], item["tested_url"], item["evidence"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


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
