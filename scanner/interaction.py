"""
Form Interaction Engine.
Fills inputs, clicks buttons, captures newly revealed APIs and pages.
Works generically on any website — no site-specific logic.
"""

import tempfile
import os
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError

from .crawler import page_state_hash, collect_elements, nav_back

ELEM_TIMEOUT = 3_000   # ms per element action


# ── Network capture ────────────────────────────────────────────────

def wait_and_capture(page, api_calls: set, snapshot_before: set, cfg: dict) -> set:
    """Wait for network idle + buffer, return newly fired API calls."""
    try:
        page.wait_for_load_state("networkidle", timeout=cfg["network_idle_wait"])
    except PlaywrightTimeoutError:
        pass
    except Exception:
        pass
    page.wait_for_timeout(cfg["post_click_wait"])
    return api_calls - snapshot_before


# ── Smart fill ─────────────────────────────────────────────────────

def smart_fill(inp, itype: str, iid: str, cfg: dict) -> str | None:
    test_values = cfg["test_values"]
    itype = itype.lower()

    if itype in test_values:
        value = test_values[itype]
        inp.fill(str(value), timeout=ELEM_TIMEOUT)
        return f"✍️  Filled [{itype}] '{iid}' → '{value}'"

    skip = ("checkbox","radio","file","hidden","button","submit","reset","image")
    if itype not in skip:
        value = test_values.get("text", "test")
        inp.fill(str(value), timeout=ELEM_TIMEOUT)
        return f"✍️  Filled [unknown:{itype}] '{iid}' → '{value}'"

    return None


# ── Button scorer JS ───────────────────────────────────────────────

SCORE_ALL_JS = """
() => {
    const hardSkip = ['delete','remove','logout','log out','sign out',
                      'purchase','pay','checkout','buy','deactivate',
                      'unsubscribe','wipe','destroy','terminate'];

    const buttons = Array.from(document.querySelectorAll('button'));
    const vh = window.innerHeight || document.documentElement.clientHeight;

    return buttons.map((btn, idx) => {
        const text = (btn.innerText || '').replace(/\\s+/g,' ').trim().toLowerCase();
        for (const w of hardSkip) {
            if (text.includes(w)) return { idx, text, score: -999 };
        }
        let score = 0;
        if (btn.closest('form'))   score += 30;
        if ((btn.getAttribute('type')||'').toLowerCase() === 'submit') score += 20;
        const cls = (btn.className||'').toLowerCase();
        if (cls.includes('primary')||cls.includes('submit')||
            cls.includes('solid')  ||cls.includes('cta')||
            cls.includes('main')   ||cls.includes('action')) score += 15;
        if (btn.closest('header')||btn.closest('nav')||
            btn.closest('footer')) score -= 50;
        const rect = btn.getBoundingClientRect();
        if (vh > 0) {
            const relY = rect.top / vh;
            if (relY > 0.6)  score += 10;
            if (relY < 0.15) score -= 20;
        }
        const container = btn.closest(
            'section,article,main,form,[class*="card"],[class*="panel"],' +
            '[class*="wrap"],[class*="container"]'
        );
        if (container) {
            const ni = container.querySelectorAll('input:not([type=hidden]),textarea,select');
            if (ni.length > 0) score += 10;
        }
        return { idx, text, score };
    });
}
"""

CUSTOM_DROPDOWN_JS = """
() => {
    const triggers = Array.from(document.querySelectorAll(
        '[role="combobox"],[aria-haspopup="listbox"],[aria-haspopup="true"],' +
        '[aria-expanded],[data-toggle],.select__control,.dropdown-toggle,' +
        '[class*="dropdown"][class*="trigger"],[class*="select"][class*="control"],' +
        '[class*="combo"]'
    )).filter(el => {
        const t = el.tagName.toLowerCase();
        return t !== 'select' && t !== 'input';
    });
    return triggers.map((el, idx) => ({
        idx,
        tag:  el.tagName,
        role: el.getAttribute('role') || '',
        text: (el.innerText||'').replace(/\\s+/g,' ').trim().slice(0,60),
        id:   el.id || el.getAttribute('name') || '',
    }));
}
"""


# ── Main interaction function ──────────────────────────────────────

def interact_with_page(
    page, url: str, results: dict,
    api_calls: set, visited_pages: set, visited_states: set, cfg: dict
) -> set:
    """
    Fill all inputs, handle dropdowns, click all non-destructive buttons.
    Returns set of newly discovered internal URLs.
    """

    print(f"\n   🤖 Interacting with form elements on: {url}")

    sample_file   = _create_sample_file()
    new_urls      = set()
    reported_apis = set(api_calls)
    radio_groups_done = set()

    def flush_new_apis(label=""):
        nonlocal reported_apis
        for call in sorted(api_calls - reported_apis):
            tag = f" [{label}]" if label else ""
            print(f"      📡 New API discovered{tag}: {call}")
        reported_apis = set(api_calls)

    def snapshot():
        new = collect_elements(page, page.url, results)
        fresh = new - visited_pages
        new_urls.update(fresh)
        for u in fresh:
            print(f"      🔗 New page discovered: {u}")

    # ── 1. Inputs ─────────────────────────────────────────────────
    try:
        all_inputs = page.locator("input").all()
    except Exception:
        all_inputs = []

    for inp in all_inputs:
        try:
            itype = (inp.get_attribute("type") or "text").lower()
            iid   = (inp.get_attribute("id") or inp.get_attribute("name")
                     or inp.get_attribute("placeholder") or itype)

            if itype == "checkbox":
                try:
                    page.evaluate("el => el.click()", inp.element_handle())
                    print(f"      ☑️  Clicked checkbox '{iid}'")
                except Exception as e:
                    print(f"      ⚠️  Checkbox '{iid}' skipped: {e}")

            elif itype == "radio":
                group = inp.get_attribute("name") or iid
                if group not in radio_groups_done:
                    try:
                        page.evaluate("el => el.click()", inp.element_handle())
                        radio_groups_done.add(group)
                        print(f"      🔘 Radio '{iid}' (group: '{group}')")
                    except Exception as e:
                        print(f"      ⚠️  Radio '{iid}' skipped: {e}")

            elif itype == "file":
                try:
                    inp.set_input_files(sample_file, timeout=ELEM_TIMEOUT)
                    print(f"      📎 Uploaded sample file to '{iid}'")
                except Exception as e:
                    print(f"      ⚠️  File input '{iid}' skipped: {e}")

            elif itype in ("hidden","button","submit","reset","image"):
                pass

            else:
                try:
                    msg = smart_fill(inp, itype, iid, cfg)
                    if msg:
                        print(f"      {msg}")
                except Exception as e:
                    print(f"      ⚠️  Input '{iid}' ({itype}) skipped: {e}")

        except Exception as e:
            print(f"      ⚠️  Input element error: {e}")

    # ── 2. Textareas ──────────────────────────────────────────────
    try:
        for ta in page.locator("textarea").all():
            try:
                ta_id = (ta.get_attribute("id") or ta.get_attribute("name")
                         or ta.get_attribute("placeholder") or "textarea")
                val = cfg["test_values"].get("textarea", "Test content")
                ta.scroll_into_view_if_needed(timeout=ELEM_TIMEOUT)
                ta.fill(val, timeout=ELEM_TIMEOUT)
                print(f"      ✍️  Filled [textarea] '{ta_id}' → '{val}'")
            except Exception as e:
                print(f"      ⚠️  Textarea skipped: {e}")
    except Exception:
        pass

    # ── 3. Native selects ─────────────────────────────────────────
    try:
        for sel in page.locator("select").all():
            try:
                sel_id = sel.get_attribute("id") or sel.get_attribute("name") or "select"
                chosen = None
                for opt in sel.locator("option").all():
                    val = (opt.get_attribute("value") or "").strip()
                    if val:
                        chosen = val
                        break
                if chosen:
                    sel.select_option(chosen, timeout=ELEM_TIMEOUT)
                    print(f"      📋 Selected dropdown '{sel_id}' → '{chosen}'")
            except Exception as e:
                print(f"      ⚠️  Select skipped: {e}")
    except Exception:
        pass

    # ── 4. Custom dropdowns ───────────────────────────────────────
    try:
        custom_dropdowns = page.evaluate(CUSTOM_DROPDOWN_JS)
    except Exception:
        custom_dropdowns = []

    if custom_dropdowns:
        print(f"      🔽 Found {len(custom_dropdowns)} custom dropdown(s)")

    for dd in custom_dropdowns:
        try:
            dd_id = dd.get("id") or dd.get("text", "dropdown")
            locator = page.locator(
                '[role="combobox"],[aria-haspopup="listbox"],[aria-haspopup="true"],'
                '[aria-expanded],.select__control,[class*="dropdown"][class*="trigger"],'
                '[class*="select"][class*="control"]'
            ).nth(dd.get("idx", 0))
            locator.click(timeout=ELEM_TIMEOUT)
            page.wait_for_timeout(800)
            option = page.locator(
                '[role="option"]:not([aria-disabled="true"]),'
                '[role="listbox"] li:not([aria-disabled="true"]),'
                '.select__option,[class*="dropdown"] li,[class*="option-item"]'
            ).first
            if option.count() > 0:
                opt_text = " ".join(option.inner_text().split())
                option.click(timeout=ELEM_TIMEOUT)
                print(f"      📋 Custom dropdown '{dd_id}' → '{opt_text}'")
            else:
                page.keyboard.press("Escape")
                print(f"      ⚠️  Custom dropdown '{dd_id}' opened, no options found")
            page.wait_for_timeout(500)
        except Exception as e:
            print(f"      ⚠️  Custom dropdown skipped: {e}")
            try:
                page.keyboard.press("Escape")
            except Exception:
                pass

    try:
        page.keyboard.press("Escape")
    except Exception:
        pass

    page.wait_for_timeout(cfg["interaction_wait"])
    flush_new_apis("after fill")
    snapshot()

    # ── 5. Buttons ────────────────────────────────────────────────
    try:
        button_scores = page.evaluate(SCORE_ALL_JS)
    except Exception as e:
        print(f"      ⚠️  Button scoring failed: {e}")
        button_scores = []

    button_scores.sort(key=lambda x: x.get("score", -999), reverse=True)

    try:
        all_btn_handles = page.locator("button").all()
    except Exception:
        all_btn_handles = []

    print(f"      🔎 Found {len(all_btn_handles)} button(s) on page")

    for item in button_scores:
        idx      = item.get("idx", -1)
        score    = item.get("score", 0)
        raw_text = " ".join((item.get("text") or "").split())

        if not raw_text or score <= -999:
            if score <= -999:
                print(f"      🚫 Skipping destructive button: '{raw_text}'")
            continue

        if idx < 0 or idx >= len(all_btn_handles):
            continue

        btn = all_btn_handles[idx]
        try:
            api_before   = set(api_calls)
            state_before = page_state_hash(page)

            print(f"      🖱️  Clicking button: '{raw_text}' (score={score})")

            clicked = False
            try:
                btn.scroll_into_view_if_needed(timeout=3_000)
                btn.click(timeout=5_000)
                clicked = True
            except Exception as e1:
                print(f"         ⚠️  Normal click failed: {e1}")
                try:
                    btn.click(force=True, timeout=5_000)
                    clicked = True
                    print(f"         ✅ Force click succeeded")
                except Exception as e2:
                    print(f"         ❌ Force click also failed: {e2}")

            if not clicked:
                continue

            new_calls = wait_and_capture(page, api_calls, api_before, cfg)
            for call in sorted(new_calls):
                print(f"      📡 New API discovered [after '{raw_text}']: {call}")
            reported_apis = set(api_calls)

            state_after = page_state_hash(page)

            if state_after and state_after == state_before:
                print(f"      ℹ️  No state change after '{raw_text}'")
                if page.url.rstrip("/") != url.rstrip("/"):
                    nav_back(page, url, cfg)
                continue

            if state_after and state_after in visited_states:
                print(f"      ♻️  State already explored, going back")
                nav_back(page, url, cfg)
                continue

            if state_after:
                visited_states.add(state_after)

            snapshot()

            if page.url.rstrip("/") != url.rstrip("/"):
                print(f"      ↩️  Left page → {page.url}, returning to {url}")
                nav_back(page, url, cfg)
                try:
                    button_scores_new = page.evaluate(SCORE_ALL_JS)
                    all_btn_handles = page.locator("button").all()
                    button_scores = button_scores_new
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


def _create_sample_file() -> str:
    tmp = tempfile.NamedTemporaryFile(
        delete=False, suffix=".txt", mode="w", encoding="utf-8"
    )
    tmp.write("security_test_sample_upload")
    tmp.close()
    return tmp.name
