"""
Scan engine — async, uses async_playwright.

Why async_playwright instead of sync_playwright:
  sync_playwright internally calls asyncio.create_subprocess_exec() to launch
  Chromium. On Windows, this only works from the main thread's event loop.
  When called from a FastAPI worker thread (run_in_executor) it raises
  NotImplementedError regardless of which event loop type is installed.

  async_playwright runs natively inside the existing asyncio event loop that
  FastAPI/uvicorn owns. No threads needed. No subprocess-from-thread issue.

All scanner sub-modules (crawler, interaction, headers, cookies, ssl_check)
remain synchronous — they are called directly since this engine owns the
async/await boundary.  Playwright async objects (page, browser, response)
accept both awaitable and direct calls; we await only what is necessary.
"""

import hashlib
from datetime import datetime
from playwright.async_api import async_playwright

from scanner.crawler                import normalise_url, is_internal
from scanner.headers                import check_headers
from scanner.auth_surface_detector  import detect_auth_surface
from scanner.cookies                import analyse_cookies
from scanner.ssl_check              import check_ssl, evaluate_ssl
from scanner.http_method_analyzer   import analyze_http_methods
from scanner.javascript_secret_scanner import scan_javascript_secrets
from scanner.dom_xss_scanner         import scan_dom_xss
from scanner.directory_listing_scanner import scan_directory_listing
from scanner.forced_browsing_scanner import scan_forced_browsing
from scanner.graphql_introspection_scanner import scan_graphql_introspection
from scanner.open_redirect_scanner  import scan_open_redirect
from scanner.reflected_xss_scanner  import scan_reflected_xss
from scanner.source_map_scanner     import scan_source_maps
from scanner.stored_xss_scanner     import scan_stored_xss
from scanner.sql_injection_scanner  import scan_sql_injection
from scanner.technology_fingerprinter import fingerprint_technology
from scanner.api_rate_limit_scanner import scan_api_rate_limits
from scanner.csrf_scanner           import analyze_csrf_risk
from scanner.sensitive_path_prober  import probe_sensitive_paths
from scanner.cors_security_analyzer import analyze_cors_security
from scanner.verbose_error_scanner  import scan_verbose_errors


def _emit_progress(progress, current_step: str, **metrics) -> None:
    if progress is None:
        return

    try:
        progress({"current_step": current_step, **metrics})
    except Exception:
        pass


def _emit_event(progress, level: str, phase: str, message: str, **data) -> None:
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


# ── Async element collector (mirrors sync version in crawler.py) ───

async def _collect_elements_async(page, url: str, results: dict, progress=None) -> set:
    """Async version of collect_elements — iterates async locators."""

    # FORMS
    try:
        forms = await page.locator("form").all()
        for idx, form in enumerate(forms):
            try:
                entry = {
                    "page":    url,
                    "form_no": idx + 1,
                    "action":  await form.get_attribute("action"),
                    "method":  await form.get_attribute("method"),
                    "id":      await form.get_attribute("id"),
                }
                if entry not in results["forms"]:
                    results["forms"].append(entry)
                    _emit_event(
                        progress,
                        "info",
                        "discovery",
                        "Form discovered",
                        url=url,
                        form_no=entry["form_no"],
                        action=entry["action"],
                        method=entry["method"],
                        element_id=entry["id"],
                    )
            except Exception:
                pass
    except Exception:
        pass

    # INPUTS
    try:
        inputs = await page.locator("input").all()
        for inp in inputs:
            try:
                entry = {
                    "page":        url,
                    "id":          await inp.get_attribute("id"),
                    "name":        await inp.get_attribute("name"),
                    "type":        (await inp.get_attribute("type")) or "text",
                    "placeholder": await inp.get_attribute("placeholder"),
                    "required":    (await inp.get_attribute("required")) is not None,
                }
                if entry not in results["inputs"]:
                    results["inputs"].append(entry)
                    _emit_event(
                        progress,
                        "info",
                        "discovery",
                        "Input discovered",
                        url=url,
                        input_type=entry["type"],
                        name=entry["name"],
                        element_id=entry["id"],
                        required=entry["required"],
                    )
            except Exception:
                pass
    except Exception:
        pass

    # TEXTAREAS
    try:
        textareas = await page.locator("textarea").all()
        for ta in textareas:
            try:
                entry = {
                    "page":        url,
                    "id":          await ta.get_attribute("id"),
                    "name":        await ta.get_attribute("name"),
                    "type":        "textarea",
                    "placeholder": await ta.get_attribute("placeholder"),
                    "required":    (await ta.get_attribute("required")) is not None,
                }
                if entry not in results["inputs"]:
                    results["inputs"].append(entry)
                    _emit_event(
                        progress,
                        "info",
                        "discovery",
                        "Textarea discovered",
                        url=url,
                        name=entry["name"],
                        element_id=entry["id"],
                        required=entry["required"],
                    )
            except Exception:
                pass
    except Exception:
        pass

    # BUTTONS
    try:
        btns = await page.locator("button").all()
        for btn in btns:
            try:
                text = " ".join((await btn.inner_text()).split())
                if text and text not in results["buttons"]:
                    results["buttons"].append(text)
                    _emit_event(
                        progress,
                        "info",
                        "discovery",
                        "Button discovered",
                        url=url,
                        button=text,
                    )
            except Exception:
                pass
    except Exception:
        pass

    # LINKS
    found = set()
    try:
        links = await page.locator("a").all()
        for link in links:
            try:
                href = await link.get_attribute("href")
                if not href:
                    continue
                from urllib.parse import urljoin
                full = normalise_url(urljoin(url, href))
                if is_internal(url, full):
                    found.add(full)
                    _emit_event(
                        progress,
                        "info",
                        "discovery",
                        "Internal link discovered",
                        source_url=url,
                        discovered_url=full,
                    )
            except Exception:
                pass
    except Exception:
        pass

    return found


async def _page_state_hash_async(page) -> str | None:
    """
    MD5 of current URL + visible input IDs + button texts.
    Used to detect identical UI states and prevent interaction loops.
    """
    try:
        parts = [page.url]

        visible_fields = await page.locator(
            "input:visible, textarea:visible, select:visible"
        ).all()
        for el in visible_fields:
            try:
                parts.append(
                    (await el.get_attribute("id"))
                    or (await el.get_attribute("name"))
                    or ""
                )
            except Exception:
                pass

        buttons = await page.locator("button").all()
        for btn in buttons:
            try:
                parts.append(" ".join((await btn.inner_text()).split())[:60])
            except Exception:
                pass

        return hashlib.md5("|".join(parts).encode()).hexdigest()
    except Exception:
        return None


# ── Async interaction engine ───────────────────────────────────────

SCORE_ALL_JS = """
() => {
    const hardSkip = ['delete','remove','logout','log out','sign out',
                      'purchase','pay','checkout','buy','deactivate',
                      'unsubscribe','wipe','destroy','terminate'];
    const buttons = Array.from(document.querySelectorAll('button'));
    const vh = window.innerHeight || document.documentElement.clientHeight;
    return buttons.map((btn, idx) => {
        const text = (btn.innerText||'').replace(/\\s+/g,' ').trim().toLowerCase();
        for (const w of hardSkip) {
            if (text.includes(w)) return { idx, text, score: -999 };
        }
        let score = 0;
        if (btn.closest('form'))   score += 30;
        if ((btn.getAttribute('type')||'').toLowerCase()==='submit') score += 20;
        const cls = (btn.className||'').toLowerCase();
        if (cls.includes('primary')||cls.includes('submit')||cls.includes('solid')||
            cls.includes('cta')    ||cls.includes('main')  ||cls.includes('action')) score += 15;
        if (btn.closest('header')||btn.closest('nav')||btn.closest('footer')) score -= 50;
        const rect = btn.getBoundingClientRect();
        if (vh > 0) {
            const relY = rect.top / vh;
            if (relY > 0.6)  score += 10;
            if (relY < 0.15) score -= 20;
        }
        const c = btn.closest('section,article,main,form,[class*="card"],[class*="panel"],[class*="wrap"],[class*="container"]');
        if (c && c.querySelectorAll('input:not([type=hidden]),textarea,select').length > 0) score += 10;
        return { idx, text, score };
    });
}
"""

ELEM_TO = 3_000


async def _is_usable_element(locator) -> bool:
    try:
        if not await locator.is_visible():
            return False
        if not await locator.is_enabled():
            return False
        if await locator.get_attribute("disabled") is not None:
            return False
        if await locator.get_attribute("readonly") is not None:
            return False
        return True
    except Exception:
        return False


async def _interact_async(page, url: str, results: dict,
                           api_calls: set, visited_pages: set,
                           visited_states: set, cfg: dict,
                           progress=None) -> set:
    """Async form interaction engine."""

    print(f"\n   🤖 Interacting with form elements on: {url}")

    _emit_event(progress, "info", "interaction", "Interacting with page", url=url)

    import tempfile, os
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".txt", mode="w", encoding="utf-8")
    tmp.write("security_test_sample_upload")
    tmp.close()
    sample_file = tmp.name

    new_urls      = set()
    reported_apis = set(api_calls)
    radio_done    = set()

    def flush_apis(label=""):
        nonlocal reported_apis
        for call in sorted(api_calls - reported_apis):
            tag = f" [{label}]" if label else ""
            print(f"      📡 New API discovered{tag}: {call}")
        for call in sorted(api_calls - reported_apis):
            _emit_event(
                progress,
                "info",
                "api",
                "API request discovered",
                url=call,
                context=label or None,
            )
        reported_apis = set(api_calls)

    async def snapshot():
        new   = await _collect_elements_async(page, page.url, results, progress)
        fresh = new - visited_pages
        new_urls.update(fresh)
        for u in fresh:
            _emit_event(
                progress,
                "info",
                "crawl",
                "New page discovered",
                url=u,
                source_url=page.url,
            )
            print(f"      🔗 New page discovered: {u}")

    tv = cfg["test_values"]

    # ── Inputs ────────────────────────────────────────────────────
    try:
        all_inputs = await page.locator("input").all()
    except Exception:
        all_inputs = []

    for inp in all_inputs:
        try:
            itype = ((await inp.get_attribute("type")) or "text").lower()
            iid   = ((await inp.get_attribute("id")) or
                     (await inp.get_attribute("name")) or
                     (await inp.get_attribute("placeholder")) or itype)

            if itype not in ("hidden", "button", "submit", "reset", "image"):
                if not await _is_usable_element(inp):
                    continue

            if itype == "checkbox":
                try:
                    await page.evaluate("el => el.click()", await inp.element_handle())
                    _emit_event(progress, "info", "interaction", "Checkbox clicked", url=url, field=iid)
                    print(f"      ☑️  Clicked checkbox '{iid}'")
                except Exception as e:
                    print(f"      ⚠️  Checkbox '{iid}' skipped: {e}")

            elif itype == "radio":
                group = (await inp.get_attribute("name")) or iid
                if group not in radio_done:
                    try:
                        await page.evaluate("el => el.click()", await inp.element_handle())
                        radio_done.add(group)
                        _emit_event(progress, "info", "interaction", "Radio selected", url=url, field=iid, group=group)
                        print(f"      🔘 Radio '{iid}' (group '{group}')")
                    except Exception as e:
                        print(f"      ⚠️  Radio '{iid}' skipped: {e}")

            elif itype == "file":
                try:
                    await inp.set_input_files(sample_file, timeout=ELEM_TO)
                    _emit_event(progress, "info", "interaction", "File uploaded", url=url, field=iid)
                    print(f"      📎 Uploaded file to '{iid}'")
                except Exception as e:
                    print(f"      ⚠️  File '{iid}' skipped: {e}")

            elif itype in ("hidden","button","submit","reset","image"):
                pass

            else:
                val = tv.get(itype) or tv.get("text", "test")
                try:
                    await inp.fill(str(val), timeout=1_200)
                    _emit_event(
                        progress,
                        "info",
                        "interaction",
                        "Input filled",
                        url=url,
                        field=iid,
                        input_type=itype,
                        value=str(val),
                    )
                    print(f"      ✍️  Filled [{itype}] '{iid}' → '{val}'")
                except Exception as e:
                    print(f"      ⚠️  Input '{iid}' skipped: {e}")

        except Exception as e:
            print(f"      ⚠️  Input error: {e}")

    # ── Textareas ─────────────────────────────────────────────────
    try:
        for ta in await page.locator("textarea").all():
            try:
                if not await _is_usable_element(ta):
                    continue
                ta_id = ((await ta.get_attribute("id")) or
                         (await ta.get_attribute("name")) or "textarea")
                val = tv.get("textarea", "Test content")
                await ta.scroll_into_view_if_needed(timeout=1_000)
                await ta.fill(val, timeout=1_200)
                _emit_event(progress, "info", "interaction", "Textarea filled", url=url, field=ta_id, value=val)
                print(f"      ✍️  Filled [textarea] '{ta_id}' → '{val}'")
            except Exception as e:
                print(f"      ⚠️  Textarea skipped: {e}")
    except Exception:
        pass

    # ── Native selects ────────────────────────────────────────────
    try:
        for sel in await page.locator("select").all():
            try:
                if not await _is_usable_element(sel):
                    continue
                sel_id = ((await sel.get_attribute("id")) or
                          (await sel.get_attribute("name")) or "select")
                chosen = None
                for opt in await sel.locator("option").all():
                    v = ((await opt.get_attribute("value")) or "").strip()
                    if v:
                        chosen = v
                        break
                if chosen:
                    await sel.select_option(chosen, timeout=1_200)
                    _emit_event(progress, "info", "interaction", "Select option chosen", url=url, field=sel_id, value=chosen)
                    print(f"      📋 Select '{sel_id}' → '{chosen}'")
            except Exception as e:
                print(f"      ⚠️  Select skipped: {e}")
    except Exception:
        pass

    await page.wait_for_timeout(cfg["interaction_wait"])
    flush_apis("after fill")
    await snapshot()

    # ── Buttons ───────────────────────────────────────────────────
    try:
        button_scores = await page.evaluate(SCORE_ALL_JS)
    except Exception as e:
        print(f"      ⚠️  Button scoring failed: {e}")
        button_scores = []

    button_scores.sort(key=lambda x: x.get("score", -999), reverse=True)

    try:
        all_btns = await page.locator("button").all()
    except Exception:
        all_btns = []

    _emit_event(progress, "info", "interaction", "Buttons found on page", url=url, count=len(all_btns))

    print(f"      🔎 Found {len(all_btns)} button(s) on page")

    max_button_interactions = 6
    buttons_attempted = 0

    for item in button_scores:
        idx      = item.get("idx", -1)
        score    = item.get("score", 0)
        raw_text = " ".join((item.get("text") or "").split())

        if not raw_text:
            continue
        if score <= -999:
            _emit_event(progress, "warning", "interaction", "Skipping destructive button", url=url, button=raw_text, score=score)
            print(f"      🚫 Skipping destructive button: '{raw_text}'")
            continue
        if idx < 0 or idx >= len(all_btns):
            continue
        if buttons_attempted >= max_button_interactions:
            print(f"      ℹ️  Button interaction cap reached on {url}")
            break

        btn = all_btns[idx]
        try:
            if not await _is_usable_element(btn):
                continue
            api_before   = set(api_calls)
            state_before = await _page_state_hash_async(page)
            buttons_attempted += 1

            print(f"      🖱️  Clicking button: '{raw_text}' (score={score})")

            _emit_event(progress, "info", "interaction", "Clicking button", url=url, button=raw_text, score=score)

            clicked = False
            try:
                await btn.scroll_into_view_if_needed(timeout=1_000)
                await btn.click(timeout=1_500)
                clicked = True
                _emit_event(progress, "info", "interaction", "Button clicked", url=url, button=raw_text)
            except Exception as e1:
                print(f"         ⚠️  Normal click failed: {e1}")
                try:
                    await btn.click(force=True, timeout=1_200)
                    clicked = True
                    _emit_event(progress, "info", "interaction", "Force button click succeeded", url=url, button=raw_text)
                    print(f"         ✅ Force click succeeded")
                except Exception as e2:
                    print(f"         ❌ Force click failed: {e2}")

            if not clicked:
                continue

            try:
                await page.wait_for_load_state("networkidle",
                                               timeout=cfg["network_idle_wait"])
            except Exception:
                pass
            await page.wait_for_timeout(cfg["post_click_wait"])

            new_calls = api_calls - api_before
            for call in sorted(new_calls):
                if is_internal(url, call):
                    _emit_event(progress, "info", "api", "API request discovered after button click", url=call, button=raw_text)
                    print(f"      📡 New API [after '{raw_text}']: {call}")
            reported_apis = set(api_calls)

            state_after = await _page_state_hash_async(page)

            if state_after and state_after == state_before:
                print(f"      ℹ️  No state change after '{raw_text}'")
                if page.url.rstrip("/") != url.rstrip("/"):
                    await page.goto(url, wait_until="networkidle",
                                    timeout=cfg["page_timeout"])
                continue

            if state_after and state_after in visited_states:
                print(f"      ♻️  State already explored, going back")
                await page.goto(url, wait_until="networkidle",
                                timeout=cfg["page_timeout"])
                continue

            if state_after:
                visited_states.add(state_after)

            await snapshot()

            if page.url.rstrip("/") != url.rstrip("/"):
                print(f"      ↩️  Left page, returning to {url}")
                await page.goto(url, wait_until="networkidle",
                                timeout=cfg["page_timeout"])
                await page.wait_for_timeout(1_000)
                try:
                    button_scores = await page.evaluate(SCORE_ALL_JS)
                    all_btns = await page.locator("button").all()
                    button_scores.sort(key=lambda x: x.get("score", -999), reverse=True)
                except Exception:
                    pass

        except Exception as e:
            print(f"      ❌ Button '{raw_text}' error: {e}")

    try:
        os.unlink(sample_file)
    except Exception:
        pass

    return new_urls


# ── Main async scan entry point ────────────────────────────────────

async def run_scan(target_url: str, cfg: dict, progress=None) -> dict:
    """
    Full async scan pipeline.
    Called directly from FastAPI async endpoint — no threads needed.
    """

    start_url  = normalise_url(target_url)
    max_pages  = cfg.get("max_pages", 20)
    max_depth  = cfg.get("max_depth", 2)
    scan_time  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    api_calls      = set()
    visited_pages  = set()
    visited_states = set()
    pending_pages  = {(start_url, 0)}

    results = {
        "target":                    start_url,
        "scan_time":                 scan_time,
        "pages":                     [],
        "forms":                     [],
        "inputs":                    [],
        "buttons":                   [],
        "api_calls":                 [],
        "security_headers":          {},
        "cookies":                   [],
        "auth_surface":              {},
        "ssl":                       {},
        "http_methods":              {},
        "javascript_secrets":        {},
        "technology_fingerprint":    {},
        "graphql":                   {},
        "api_rate_limiting":         {},
        "csrf":                      {},
        "source_maps":               {},
        "directory_listing":         {},
        "forced_browsing":           {},
        "verbose_errors":            {},
        "dom_xss":                   [],
        "open_redirect":             [],
        "reflected_xss":             [],
        "stored_xss":                [],
        "sql_injection":             [],
        "sensitive_paths":           [],
        "cors_analysis":             {},
        "findings":                  [],
    }

    def publish(current_step: str, **extra) -> None:
        _emit_progress(
            progress,
            current_step,
            pages_found=len(visited_pages),
            forms_found=len(results["forms"]),
            inputs_found=len(results["inputs"]),
            buttons_found=len(results["buttons"]),
            api_calls_found=len(api_calls),
            findings_found=len(results["findings"]),
            pending_pages=len(pending_pages),
            **extra,
        )
        _emit_event(progress, "info", "scan", current_step, **extra)

    print("\n" + "=" * 60)
    print("🛡️  SECURITY TESTING STARTED")
    print("=" * 60)
    print(f"🌐 Target: {start_url}")
    print()

    publish("Starting scan")

    async with async_playwright() as p:

        publish("Launching browser")
        browser = await p.chromium.launch(
            headless=cfg.get("headless", True),
            slow_mo=cfg.get("slow_mo", 0),
        )
        context = await browser.new_context()
        page    = await context.new_page()

        def track_request(req):
            if req.url not in api_calls:
                if is_internal(start_url, req.url):
                    _emit_event(
                        progress,
                        "info",
                        "network",
                        "Request finished",
                        url=req.url,
                        method=req.method,
                        resource_type=req.resource_type,
                    )
            api_calls.add(req.url)

        page.on("requestfinished", track_request)

        # ── Initial load ───────────────────────────────────────────
        print("🔍 Crawling website...")
        publish("Loading target page")
        try:
            response = await page.goto(
                start_url,
                wait_until="networkidle",
                timeout=cfg["page_timeout"],
            )
        except Exception as e:
            print(f"❌ Failed to load target URL: {e}")
            await browser.close()
            return results

        if response is None:
            print("❌ No response. Aborting.")
            await browser.close()
            return results

        print("✅ Website loaded successfully")
        visited_pages.add(start_url)
        publish("Target page loaded")
        initial_html = await page.content()

        init_state = await _page_state_hash_async(page)
        if init_state:
            visited_states.add(init_state)

        # ── Security headers ───────────────────────────────────────
        print("🔐 Checking Security Headers...")
        publish("Checking security headers")
        results["security_headers"] = check_headers(
            dict(response.headers),
            cfg["required_security_headers"],
            results["findings"],
        )
        publish("Security headers checked")

        # ── Cookies ───────────────────────────────────────────────
        print("🍪 Analyzing Session Cookies...")
        publish("Analyzing cookies")
        results["cookies"] = analyse_cookies(
            await context.cookies(), results["findings"]
        )
        publish("Cookies analyzed", cookies_found=len(results["cookies"]))

        # ── Crawl + interact ───────────────────────────────────────
        publish("Discovering page elements")
        new_links = await _collect_elements_async(page, start_url, results, progress)
        publish("Initial elements discovered")
        for lnk in new_links - visited_pages:
            pending_pages.add((lnk, 1))

        publish("Detecting authentication surface")
        results["auth_surface"] = detect_auth_surface(
            start_url,
            sorted(visited_pages),
            results["forms"],
            results["inputs"],
            results["buttons"],
            sorted(api_calls),
        )
        publish("Authentication surface detection complete")

        publish("Testing open redirects")
        results["open_redirect"].extend(
            await scan_open_redirect(page, start_url, cfg, progress)
        )
        publish(
            "Open redirect testing complete",
            open_redirect_findings=len(results["open_redirect"]),
        )

        publish("Testing DOM-based XSS")
        results["dom_xss"].extend(
            await scan_dom_xss(page, start_url, cfg, progress)
        )
        publish(
            "DOM-based XSS testing complete",
            dom_xss_findings=len(results["dom_xss"]),
        )

        publish("Testing reflected XSS")
        results["reflected_xss"].extend(
            await scan_reflected_xss(page, start_url, cfg, progress)
        )
        publish(
            "Reflected XSS testing complete",
            reflected_xss_findings=len(results["reflected_xss"]),
        )

        publish("Testing stored XSS")
        results["stored_xss"].extend(
            await scan_stored_xss(page, start_url, cfg, progress)
        )
        publish(
            "Stored XSS testing complete",
            stored_xss_findings=len(results["stored_xss"]),
        )

        publish("Testing SQL injection")
        results["sql_injection"].extend(
            await scan_sql_injection(page, start_url, cfg, progress)
        )
        publish(
            "SQL injection testing complete",
            sql_injection_findings=len(results["sql_injection"]),
        )

        publish("Interacting with target page")
        inter_links = await _interact_async(
            page, start_url, results, api_calls,
            visited_pages, visited_states, cfg, progress
        )
        publish("Target page interaction complete")
        for lnk in inter_links - visited_pages:
            pending_pages.add((lnk, 1))

        while pending_pages:
            next_url, depth = pending_pages.pop()

            if next_url in visited_pages:
                continue
            if max_pages > 0 and len(visited_pages) >= max_pages:
                print(f"\n⚠️  Page limit ({max_pages}) reached — stopping crawl")
                break
            if max_depth > 0 and depth > max_depth:
                continue

            visited_pages.add(next_url)
            publish("Visiting page", current_url=next_url, current_depth=depth)
            print(f"\n🔗 Visiting (depth={depth}): {next_url}")

            try:
                resp = await page.goto(
                    next_url,
                    wait_until="networkidle",
                    timeout=cfg["page_timeout"],
                )
            except Exception as e:
                print(f"   ⚠️  Error loading {next_url}: {e}")
                continue

            if resp is None:
                continue

            more_links = await _collect_elements_async(page, next_url, results, progress)
            publish("Page elements discovered", current_url=next_url, current_depth=depth)
            for lnk in more_links - visited_pages:
                pending_pages.add((lnk, depth + 1))

            publish("Testing open redirects", current_url=next_url, current_depth=depth)
            results["open_redirect"].extend(
                await scan_open_redirect(page, next_url, cfg, progress)
            )
            publish(
                "Open redirect testing complete",
                current_url=next_url,
                current_depth=depth,
                open_redirect_findings=len(results["open_redirect"]),
            )

            publish("Testing DOM-based XSS", current_url=next_url, current_depth=depth)
            results["dom_xss"].extend(
                await scan_dom_xss(page, next_url, cfg, progress)
            )
            publish(
                "DOM-based XSS testing complete",
                current_url=next_url,
                current_depth=depth,
                dom_xss_findings=len(results["dom_xss"]),
            )

            publish("Testing reflected XSS", current_url=next_url, current_depth=depth)
            results["reflected_xss"].extend(
                await scan_reflected_xss(page, next_url, cfg, progress)
            )
            publish(
                "Reflected XSS testing complete",
                current_url=next_url,
                current_depth=depth,
                reflected_xss_findings=len(results["reflected_xss"]),
            )

            publish("Testing stored XSS", current_url=next_url, current_depth=depth)
            results["stored_xss"].extend(
                await scan_stored_xss(page, next_url, cfg, progress)
            )
            publish(
                "Stored XSS testing complete",
                current_url=next_url,
                current_depth=depth,
                stored_xss_findings=len(results["stored_xss"]),
            )

            publish("Testing SQL injection", current_url=next_url, current_depth=depth)
            results["sql_injection"].extend(
                await scan_sql_injection(page, next_url, cfg, progress)
            )
            publish(
                "SQL injection testing complete",
                current_url=next_url,
                current_depth=depth,
                sql_injection_findings=len(results["sql_injection"]),
            )

            il = await _interact_async(
                page, next_url, results, api_calls,
                visited_pages, visited_states, cfg, progress
            )
            publish("Page interaction complete", current_url=next_url, current_depth=depth)
            for lnk in il - visited_pages:
                pending_pages.add((lnk, depth + 1))

        if results["open_redirect"]:
            results["findings"].append({
                "vulnerability": "Open Redirect",
                "severity": "High",
                "details": [
                    f"{item['vector']} on {item['tested_url']}: {item['evidence']}"
                    for item in results["open_redirect"][:12]
                ],
                "redirect_vectors": results["open_redirect"],
            })

        if results["dom_xss"]:
            results["findings"].append({
                "vulnerability": "DOM-Based XSS",
                "severity": "High",
                "details": [
                    f"{item['vector']} on {item['tested_url']}: {item['evidence']}"
                    for item in results["dom_xss"][:12]
                ],
                "dom_xss_vectors": results["dom_xss"],
            })

        if results["reflected_xss"]:
            results["findings"].append({
                "vulnerability": "Reflected XSS",
                "severity": "High",
                "details": [
                    f"{item['vector']} on {item['tested_url']}: {item['evidence']}"
                    for item in results["reflected_xss"][:12]
                ],
                "xss_vectors": results["reflected_xss"],
            })

        if results["stored_xss"]:
            results["findings"].append({
                "vulnerability": "Stored XSS",
                "severity": "High",
                "details": [
                    f"{item['vector']} on {item['tested_url']}: {item['evidence']}"
                    for item in results["stored_xss"][:12]
                ],
                "stored_xss_vectors": results["stored_xss"],
            })

        if results["sql_injection"]:
            results["findings"].append({
                "vulnerability": "SQL Injection",
                "severity": "High",
                "details": [
                    f"{item['vector']} on {item['tested_url']}: {item['evidence']}"
                    for item in results["sql_injection"][:12]
                ],
                "sqli_vectors": results["sql_injection"],
            })

        publish("Refreshing authentication surface classification")
        results["auth_surface"] = detect_auth_surface(
            start_url,
            sorted(visited_pages),
            results["forms"],
            results["inputs"],
            results["buttons"],
            sorted(api_calls),
        )
        publish("Authentication coverage classification complete")

        # ── SSL (sync — no browser needed) ────────────────────────
        print("\n🔒 Validating SSL Certificate...")
        print("\nInspecting HTTP methods...")
        publish("Checking HTTP methods")
        results["http_methods"] = analyze_http_methods(
            start_url, results["findings"], cfg
        )
        publish("HTTP methods checked")

        publish("Validating SSL certificate")
        results["ssl"] = check_ssl(start_url)
        evaluate_ssl(results["ssl"], results["findings"])
        publish("SSL validation complete")

        # ── Sensitive path probing (sync — urllib, no browser) ────
        print("\n🗂️  Probing Sensitive Paths...")
        publish("Probing sensitive paths")
        results["sensitive_paths"] = probe_sensitive_paths(
            start_url, results["findings"]
        )
        publish("Sensitive path probing complete",
                sensitive_paths_found=len([
                    p for p in results["sensitive_paths"]
                    if p.get("severity") not in (None, "none", "Info")
                ]))

        # ── CORS security analysis (sync — urllib, no browser) ────
        print("\n🌐 Analyzing CORS Security...")
        publish("Analyzing CORS security")
        results["cors_analysis"] = analyze_cors_security(
            start_url, results["findings"]
        )
        publish("CORS analysis complete",
                cors_issues_found=len(results["cors_analysis"].get("issues", [])))

        print("\nReviewing CSRF risk indicators...")
        publish("Analyzing CSRF risk")
        results["csrf"] = analyze_csrf_risk(
            results["forms"], results["inputs"], results["cookies"], results["findings"]
        )
        publish("CSRF risk analysis complete")

        print("\nChecking for verbose error leakage...")
        publish("Testing error handling")
        results["verbose_errors"] = scan_verbose_errors(start_url, results["findings"])
        publish("Error handling analysis complete")

        print("\nFingerprinting application technology...")
        publish("Fingerprinting technology")
        results["technology_fingerprint"] = fingerprint_technology(
            start_url, initial_html, dict(response.headers), sorted(api_calls)
        )
        publish("Technology fingerprinting complete")

        print("\nTesting GraphQL introspection exposure...")
        publish("Checking GraphQL introspection")
        results["graphql"] = scan_graphql_introspection(
            start_url, sorted(api_calls), results["findings"], cfg
        )
        publish("GraphQL introspection check complete")

        print("\nScanning JavaScript for exposed secrets...")
        publish("Scanning JavaScript for secrets")
        results["javascript_secrets"] = scan_javascript_secrets(
            start_url,
            sorted(visited_pages),
            sorted(api_calls),
            results["findings"],
            cfg,
        )
        publish(
            "JavaScript secret scan complete",
            javascript_secrets_found=len(results["javascript_secrets"].get("detections", [])),
        )

        print("\nChecking for exposed JavaScript source maps...")
        publish("Checking source maps")
        results["source_maps"] = scan_source_maps(
            start_url, sorted(api_calls), results["findings"]
        )
        publish("Source map check complete")

        print("\nChecking for directory listing exposure...")
        publish("Checking directory listing")
        results["directory_listing"] = scan_directory_listing(
            sorted(visited_pages), results["findings"]
        )
        publish("Directory listing check complete")

        print("\nChecking for forced browsing hits...")
        publish("Checking forced browsing")
        results["forced_browsing"] = scan_forced_browsing(
            start_url, sorted(visited_pages), results["findings"], cfg
        )
        publish("Forced browsing check complete")

        print("\nTesting API rate limiting...")
        publish("Testing API rate limiting")
        results["api_rate_limiting"] = scan_api_rate_limits(
            start_url, sorted(api_calls), results["findings"], cfg
        )
        publish("API rate limiting test complete")

        await browser.close()

    results["pages"]     = sorted(visited_pages)
    results["api_calls"] = sorted(api_calls)
    publish("Scan complete")

    print(f"\n🔗 Pages Discovered:      {len(results['pages'])}")
    print(f"📝 Forms Discovered:      {len(results['forms'])}")
    print(f"⌨️  Inputs Discovered:     {len(results['inputs'])}")
    print(f"🔘 Buttons Discovered:    {len(results['buttons'])}")
    print(f"📡 API Calls Captured:    {len(results['api_calls'])}")
    print(f"🗂️  Sensitive Paths Found: {len([p for p in results['sensitive_paths'] if p.get('severity') not in (None, 'none', 'Info')])}")
    print(f"🌐 CORS Issues Found:     {len(results['cors_analysis'].get('issues', []))}")
    print(f"🚨 Findings:              {len(results['findings'])}")

    return results
