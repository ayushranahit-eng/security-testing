"""
Login abuse protection scanner.

Runs a small invalid-login burst against obvious public login forms to look for
basic abuse controls such as CAPTCHA, temporary lockout, cooldown, or HTTP 429
style throttling.

This is an initial signal only. It does not prove full credential-stuffing
resilience and should not be treated as a substitute for deeper auth testing.
"""

from urllib.parse import urlparse


AUTH_ROUTE_KEYWORDS = (
    "login", "signin", "sign-in", "sign_in", "auth", "account/login",
    "member/login", "user/login", "session",
)
AUTH_BUTTON_KEYWORDS = (
    "login", "log in", "sign in", "signin", "continue", "submit",
)
USERNAME_HINTS = (
    "user", "email", "mail", "login", "account", "member", "identifier",
)
CAPTCHA_KEYWORDS = (
    "captcha", "recaptcha", "hcaptcha", "cloudflare turnstile", "i am not a robot",
)
LOCKOUT_KEYWORDS = (
    "too many attempts", "too many login attempts", "try again later",
    "temporarily blocked", "temporarily locked", "account locked",
    "rate limit", "slow down", "wait before trying again", "retry later",
    "unusual activity", "suspicious activity",
)
INVALID_CREDENTIAL_KEYWORDS = (
    "invalid password", "invalid credentials", "incorrect password",
    "incorrect username", "wrong password", "login failed",
    "authentication failed", "sign in failed",
)


async def scan_login_abuse_protection(
    page,
    target_url: str,
    discovered_pages: list,
    forms: list,
    inputs: list,
    findings: list,
    cfg: dict,
    progress=None,
) -> dict:
    candidate_pages = _candidate_login_pages(discovered_pages, forms, inputs)
    attempts_per_page = max(1, int(cfg.get("login_probe_attempts", 6)))
    max_pages = max(1, int(cfg.get("login_probe_max_pages", 2)))

    result = {
        "status": "No login form available for brute-force probe",
        "tested_pages": [],
        "candidate_pages": candidate_pages,
        "attempts_per_page": attempts_per_page,
        "captcha_observed": False,
        "lockout_observed": False,
        "throttled": False,
        "protection_observed": False,
        "note": "The scanner only probes obvious public login forms with invalid credentials.",
    }

    if not candidate_pages:
        return result

    for login_url in candidate_pages[:max_pages]:
        _emit(progress, "info", "auth_abuse", "Testing login abuse protection", url=login_url)
        page_result = await _probe_login_page(page, target_url, login_url, attempts_per_page, cfg, progress)
        if not page_result:
            continue

        result["tested_pages"].append(page_result)
        result["captcha_observed"] = result["captcha_observed"] or page_result.get("captcha_observed", False)
        result["lockout_observed"] = result["lockout_observed"] or page_result.get("lockout_observed", False)
        result["throttled"] = result["throttled"] or page_result.get("throttled", False)
        result["protection_observed"] = result["protection_observed"] or page_result.get("protection_observed", False)

        if page_result.get("protection_observed"):
            break

    if not result["tested_pages"]:
        result["status"] = "Login-related pages were discovered, but no safe login form could be probed automatically"
        return result

    if result["protection_observed"]:
        observed = []
        if result["captcha_observed"]:
            observed.append("CAPTCHA")
        if result["lockout_observed"]:
            observed.append("temporary lockout or cooldown")
        if result["throttled"]:
            observed.append("HTTP throttling")
        observed_text = ", ".join(observed) or "abuse controls"
        result["status"] = f"Login abuse protection observed ({observed_text})"
        return result

    result["status"] = "No clear login abuse protection observed in limited invalid-login probe"
    findings.append({
        "vulnerability": "Credential Stuffing Signal",
        "severity": "Medium",
        "details": [
            (
                f"No CAPTCHA, lockout, or throttle signal was observed after "
                f"{page_result.get('attempts_sent', 0)} invalid login attempt(s) on {page_result.get('url')}"
            )
            for page_result in result["tested_pages"][:3]
        ],
    })
    return result


def _candidate_login_pages(discovered_pages: list, forms: list, inputs: list) -> list:
    password_pages = {
        str(item.get("page") or "").strip()
        for item in inputs
        if str(item.get("type") or "").lower() == "password" and str(item.get("page") or "").strip()
    }
    auth_form_pages = {
        str(form.get("page") or "").strip()
        for form in forms
        if _contains_auth_keyword(form.get("action")) or _contains_auth_keyword(form.get("id"))
    }

    scored = []
    for page_url in discovered_pages:
        url = str(page_url or "").strip()
        if not url:
            continue
        score = 0
        if url in password_pages:
            score += 60
        if url in auth_form_pages:
            score += 25
        if _contains_auth_keyword(url):
            score += 40
        if score > 0:
            scored.append((score, url))

    scored.sort(key=lambda item: (-item[0], item[1]))
    return [url for _, url in scored]


async def _probe_login_page(page, target_url: str, login_url: str, attempts: int, cfg: dict, progress=None) -> dict | None:
    captured_statuses = []

    def handle_response(response):
        try:
            parsed_target = urlparse(target_url)
            parsed_response = urlparse(response.url)
            same_host = parsed_response.netloc.lower() == parsed_target.netloc.lower()
            same_subdomain = parsed_response.netloc.lower().endswith("." + parsed_target.netloc.lower())
            if same_host or same_subdomain:
                captured_statuses.append(response.status)
        except Exception:
            pass

    page.on("response", handle_response)
    try:
        try:
            await page.goto(login_url, wait_until="networkidle", timeout=cfg["page_timeout"])
        except Exception:
            return None

        login_form = await _find_login_form(page)
        if login_form is None:
            return None

        page_result = {
            "url": login_url,
            "attempts_sent": 0,
            "captcha_observed": False,
            "lockout_observed": False,
            "throttled": False,
            "protection_observed": False,
            "submit_label": await _submit_label(login_form),
            "response_statuses": [],
            "indicators": [],
            "last_observation": None,
        }

        for attempt_index in range(attempts):
            try:
                await page.goto(login_url, wait_until="networkidle", timeout=cfg["page_timeout"])
            except Exception:
                break

            login_form = await _find_login_form(page)
            if login_form is None:
                break

            submit_control = await _find_submit_control(login_form)
            username_field = await _find_username_field(login_form)
            password_field = await _find_password_field(login_form)
            if username_field is None or password_field is None:
                break

            await _fill_probe_credentials(username_field, password_field, cfg, attempt_index)
            statuses_before = len(captured_statuses)
            clicked = await _submit_login_form(login_form, submit_control)
            if not clicked:
                break

            page_result["attempts_sent"] += 1
            try:
                await page.wait_for_load_state("networkidle", timeout=cfg["network_idle_wait"])
            except Exception:
                pass
            await page.wait_for_timeout(cfg["post_click_wait"])

            recent_statuses = captured_statuses[statuses_before:]
            page_result["response_statuses"].extend(recent_statuses)
            if any(status == 429 for status in recent_statuses):
                page_result["throttled"] = True
                page_result["protection_observed"] = True
                page_result["indicators"].append("HTTP 429 observed during repeated invalid login attempts")

            observation = await _observe_login_response(page)
            page_result["last_observation"] = observation["summary"]
            for indicator in observation["indicators"]:
                if indicator not in page_result["indicators"]:
                    page_result["indicators"].append(indicator)

            if observation["captcha_observed"]:
                page_result["captcha_observed"] = True
                page_result["protection_observed"] = True
            if observation["lockout_observed"]:
                page_result["lockout_observed"] = True
                page_result["protection_observed"] = True

            if page_result["protection_observed"]:
                _emit(progress, "info", "auth_abuse", "Login abuse protection observed", url=login_url, indicators=page_result["indicators"])
                break

        return page_result if page_result["attempts_sent"] else None
    finally:
        try:
            page.remove_listener("response", handle_response)
        except Exception:
            pass


async def _find_login_form(page):
    try:
        forms = await page.locator("form").all()
    except Exception:
        forms = []

    best_form = None
    best_score = -1
    for form in forms:
        try:
            password_count = await form.locator("input[type='password']").count()
            if not password_count:
                continue
            score = 50
            submit_label = (await _submit_label(form)).lower()
            action = str((await form.get_attribute("action")) or "").lower()
            form_id = str((await form.get_attribute("id")) or "").lower()
            if any(keyword in submit_label for keyword in AUTH_BUTTON_KEYWORDS):
                score += 20
            if _contains_auth_keyword(action) or _contains_auth_keyword(form_id):
                score += 15
            user_field = await _find_username_field(form)
            if user_field is not None:
                score += 10
            if score > best_score:
                best_score = score
                best_form = form
        except Exception:
            continue
    return best_form


async def _find_username_field(form):
    try:
        fields = await form.locator("input").all()
    except Exception:
        fields = []

    best = None
    best_score = -1
    for field in fields:
        try:
            input_type = str((await field.get_attribute("type")) or "text").lower()
            if input_type in {"hidden", "password", "submit", "button", "reset", "checkbox", "radio", "file"}:
                continue
            if not await field.is_visible() or not await field.is_enabled():
                continue
            score = 10 if input_type in {"email", "text", "search"} else 0
            for attr_name in ("name", "id", "placeholder", "autocomplete"):
                value = str((await field.get_attribute(attr_name)) or "").lower()
                if any(token in value for token in USERNAME_HINTS):
                    score += 25
            if score > best_score:
                best_score = score
                best = field
        except Exception:
            continue
    return best


async def _find_password_field(form):
    try:
        fields = await form.locator("input[type='password']").all()
    except Exception:
        fields = []
    for field in fields:
        try:
            if await field.is_visible() and await field.is_enabled():
                return field
        except Exception:
            continue
    return None


async def _find_submit_control(form):
    selectors = ("button", "input[type='submit']", "input[type='button']")
    best = None
    best_score = -1
    for selector in selectors:
        try:
            controls = await form.locator(selector).all()
        except Exception:
            controls = []
        for control in controls:
            try:
                if not await control.is_visible() or not await control.is_enabled():
                    continue
                label = await _control_label(control)
                score = 10
                lowered = label.lower()
                if any(keyword in lowered for keyword in AUTH_BUTTON_KEYWORDS):
                    score += 25
                if selector == "button":
                    score += 5
                if score > best_score:
                    best = control
                    best_score = score
            except Exception:
                continue
    return best


async def _fill_probe_credentials(username_field, password_field, cfg: dict, attempt_index: int) -> None:
    email_value = cfg.get("login_probe_username", "scanner-probe@example.com")
    base_password = cfg.get("login_probe_password", "NotTheRightPassword123!")
    await username_field.fill(email_value)
    await password_field.fill(f"{base_password}{attempt_index}")


async def _submit_login_form(form, submit_control) -> bool:
    if submit_control is not None:
        try:
            await submit_control.click(timeout=1500)
            return True
        except Exception:
            try:
                await submit_control.click(force=True, timeout=1500)
                return True
            except Exception:
                pass
    try:
        await form.evaluate("(node) => node.requestSubmit()")
        return True
    except Exception:
        return False


async def _observe_login_response(page) -> dict:
    summary = "No obvious protection or error signal observed"
    indicators = []
    captcha_observed = False
    lockout_observed = False

    try:
        text = ((await page.locator("body").inner_text()) or "").lower()
    except Exception:
        text = ""

    if any(keyword in text for keyword in INVALID_CREDENTIAL_KEYWORDS):
        summary = "Invalid-credential response observed"

    if any(keyword in text for keyword in CAPTCHA_KEYWORDS):
        captcha_observed = True
        summary = "CAPTCHA challenge observed after repeated invalid login attempts"
        indicators.append("CAPTCHA wording appeared in the response")

    if any(keyword in text for keyword in LOCKOUT_KEYWORDS):
        lockout_observed = True
        summary = "Lockout or cooldown wording observed after repeated invalid login attempts"
        indicators.append("Lockout or retry-later wording appeared in the response")

    try:
        captcha_selectors = [
            "iframe[src*='recaptcha']",
            "iframe[src*='hcaptcha']",
            "[data-sitekey]",
            ".g-recaptcha",
            ".h-captcha",
            "#captcha",
            "[id*='captcha']",
            "[class*='captcha']",
        ]
        for selector in captcha_selectors:
            if await page.locator(selector).count():
                captcha_observed = True
                summary = "CAPTCHA element observed after repeated invalid login attempts"
                indicators.append(f"CAPTCHA-like element matched selector {selector}")
                break
    except Exception:
        pass

    return {
        "summary": summary,
        "indicators": indicators,
        "captcha_observed": captcha_observed,
        "lockout_observed": lockout_observed,
    }


async def _submit_label(form) -> str:
    control = await _find_submit_control(form)
    if control is None:
        return "submit"
    return await _control_label(control)


async def _control_label(control) -> str:
    try:
        tag_name = await control.evaluate("(node) => node.tagName.toLowerCase()")
    except Exception:
        tag_name = ""
    if tag_name == "button":
        try:
            return " ".join((await control.inner_text()).split()) or "button"
        except Exception:
            return "button"
    try:
        return str((await control.get_attribute("value")) or (await control.get_attribute("name")) or "submit")
    except Exception:
        return "submit"


def _contains_auth_keyword(value: str | None) -> bool:
    lowered = str(value or "").lower()
    return any(keyword in lowered for keyword in AUTH_ROUTE_KEYWORDS)


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
