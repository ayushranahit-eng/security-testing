"""
Authentication surface detector.

Identifies likely login, signup, password-reset, and other authentication
entry points from public pages, forms, inputs, buttons, and API-like routes.
"""


# Note:
# This is a coverage-classification check. It helps determine whether an
# application likely has authenticated functionality that was not assessed by an
# unauthenticated scan. It does not validate the security of the auth system by
# itself.

AUTH_ROUTE_KEYWORDS = (
    "login", "signin", "sign-in", "sign_in", "auth", "account/login",
    "register", "signup", "sign-up", "sign_up", "create-account",
    "forgot-password", "forgotpassword", "reset-password", "resetpassword",
    "password/reset", "verify-email", "otp", "mfa", "2fa", "sso",
)
AUTH_BUTTON_KEYWORDS = (
    "login", "log in", "sign in", "signin", "register", "sign up", "signup",
    "create account", "forgot password", "reset password", "continue with",
    "login with", "sign in with",
)


def detect_auth_surface(target_url: str, pages: list, forms: list, inputs: list, buttons: list, api_calls: list) -> dict:
    signals = []

    for page in pages:
        page_str = str(page or "")
        if _contains_auth_keyword(page_str):
            signals.append({"type": "route", "value": page_str})

    for form in forms:
        action = str(form.get("action") or "")
        form_id = str(form.get("id") or "")
        method = str(form.get("method") or "").upper() or "GET"
        page = str(form.get("page") or "")
        if _contains_auth_keyword(action) or _contains_auth_keyword(form_id):
            signals.append({"type": "form", "value": f"{method} form on {page}"})
        if _has_password_input_for_page(page, inputs):
            signals.append({"type": "form", "value": f"Password field discovered on {page}"})

    for button in buttons:
        label = str(button or "")
        lowered = label.lower()
        if any(keyword in lowered for keyword in AUTH_BUTTON_KEYWORDS):
            signals.append({"type": "button", "value": label})

    for call in api_calls:
        call_str = str(call or "")
        if _contains_auth_keyword(call_str):
            signals.append({"type": "api", "value": call_str})

    deduped = []
    seen = set()
    for signal in signals:
        key = (signal["type"], signal["value"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(signal)

    auth_detected = bool(deduped)
    classification = "public_only_surface" if not auth_detected else "auth_surface_detected_without_credentials"
    return {
        "status": "Authentication surface detected" if auth_detected else "No obvious authentication surface detected",
        "auth_detected": auth_detected,
        "classification": classification,
        "signals": deduped[:20],
        "note": (
            "Authentication-related functionality appears to exist. Public-only scanning does not fully assess internal authenticated workflows."
            if auth_detected
            else "No obvious login or signup surface was detected in the scanned public scope."
        ),
    }


def _contains_auth_keyword(value: str) -> bool:
    lowered = str(value or "").lower()
    return any(keyword in lowered for keyword in AUTH_ROUTE_KEYWORDS)


def _has_password_input_for_page(page: str, inputs: list) -> bool:
    for item in inputs:
        if str(item.get("page") or "") != page:
            continue
        if str(item.get("type") or "").lower() == "password":
            return True
    return False
