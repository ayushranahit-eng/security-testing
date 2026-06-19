"""
Open redirect scanner.

Looks for redirect-style parameters and validates whether attacker-controlled
absolute URLs are followed by the application.
"""

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


async def scan_open_redirect(page, url: str, cfg: dict, progress=None) -> list:
    issues = []
    issues.extend(await _scan_query_parameters(page, url, cfg, progress))
    issues.extend(await _scan_get_forms(page, url, cfg, progress))
    await _return_to_page(page, url, cfg)
    return _dedupe(issues)


async def _scan_query_parameters(page, url: str, cfg: dict, progress=None) -> list:
    parsed = urlparse(url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    redirect_names = {name.lower() for name in cfg.get("open_redirect_parameter_names", [])}
    test_url = cfg.get("open_redirect_test_url", "https://example.org/hit-open-redirect")
    issues = []

    for index, (key, _value) in enumerate(params):
        if key.lower() not in redirect_names:
            continue

        mutated = list(params)
        mutated[index] = (key, test_url)
        candidate_url = urlunparse(parsed._replace(query=urlencode(mutated, doseq=True)))
        _emit(progress, "info", "redirect", "Testing open redirect parameter", url=candidate_url, parameter=key)

        try:
            await page.goto(candidate_url, wait_until="networkidle", timeout=cfg["page_timeout"])
            final_url = page.url
            if _redirected_to_target(final_url, test_url):
                issues.append({
                    "vector": "url_parameter",
                    "parameter": key,
                    "tested_url": candidate_url,
                    "redirect_target": final_url,
                    "severity": "High",
                    "confidence": "High",
                    "evidence": f"Parameter '{key}' redirected the browser to {final_url}",
                })
                _emit(progress, "warning", "redirect", "Potential open redirect detected", url=candidate_url, parameter=key, redirect_target=final_url)
        except Exception as exc:
            _emit(progress, "warning", "redirect", "Open redirect test skipped", url=candidate_url, parameter=key, error=str(exc))
        finally:
            await _return_to_page(page, url, cfg)

    return issues


async def _scan_get_forms(page, url: str, cfg: dict, progress=None) -> list:
    redirect_names = {name.lower() for name in cfg.get("open_redirect_parameter_names", [])}
    test_url = cfg.get("open_redirect_test_url", "https://example.org/hit-open-redirect")
    issues = []

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

        method = ((await form.get_attribute("method")) or "get").strip().lower()
        if method != "get":
            continue

        candidate_fields = []
        for selector in ("input", "textarea"):
            try:
                elements = await form.locator(selector).all()
            except Exception:
                elements = []
            for element in elements:
                name = ((await element.get_attribute("name")) or (await element.get_attribute("id")) or "").strip()
                if name.lower() in redirect_names:
                    candidate_fields.append(element)

        if not candidate_fields:
            continue

        _emit(progress, "info", "redirect", "Testing open redirect form", url=url, form_method="GET")
        try:
            for field in candidate_fields:
                await field.fill(test_url)
            await form.evaluate("(node) => node.requestSubmit()")
            try:
                await page.wait_for_load_state("networkidle", timeout=cfg["network_idle_wait"])
            except Exception:
                pass
            await page.wait_for_timeout(cfg["post_click_wait"])

            final_url = page.url
            if _redirected_to_target(final_url, test_url):
                issues.append({
                    "vector": "form_submission",
                    "parameter": "GET form redirect field",
                    "tested_url": url,
                    "redirect_target": final_url,
                    "severity": "High",
                    "confidence": "Medium",
                    "evidence": f"A GET form redirected the browser to {final_url}",
                })
                _emit(progress, "warning", "redirect", "Potential open redirect detected", url=url, redirect_target=final_url)
        except Exception as exc:
            _emit(progress, "warning", "redirect", "Open redirect form test skipped", url=url, error=str(exc))

    return issues


def _redirected_to_target(final_url: str, test_url: str) -> bool:
    parsed_final = urlparse(final_url)
    parsed_test = urlparse(test_url)
    return (
        parsed_final.scheme == parsed_test.scheme
        and parsed_final.netloc == parsed_test.netloc
        and parsed_final.path.startswith(parsed_test.path)
    )


async def _return_to_page(page, url: str, cfg: dict) -> None:
    try:
        await page.goto(url, wait_until="networkidle", timeout=cfg["page_timeout"])
    except Exception:
        pass


def _dedupe(items: list) -> list:
    seen = set()
    unique = []
    for item in items:
        key = (item["vector"], item["parameter"], item["tested_url"], item["redirect_target"])
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
