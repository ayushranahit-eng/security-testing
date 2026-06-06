"""
CSRF risk detection.
"""

# Note:
# This is a token-presence and workflow-shape check. It helps flag likely CSRF
# risk, but it is not full exploit validation and does not account for all
# server-side CSRF defenses.


TOKEN_HINTS = ("csrf", "xsrf", "token", "authenticity")


def analyze_csrf_risk(forms: list, inputs: list, cookies: list, findings: list) -> dict:
    risky_forms = []
    cookie_count = len(cookies or [])

    for form in forms:
        method = (form.get("method") or "get").lower()
        if method != "post":
            continue
        page = form.get("page")
        hidden_inputs = [
            inp for inp in inputs
            if inp.get("page") == page and (inp.get("type") or "").lower() == "hidden"
        ]
        has_token = any(
            any(hint in ((inp.get("name") or "") + " " + (inp.get("id") or "")).lower() for hint in TOKEN_HINTS)
            for inp in hidden_inputs
        )
        if not has_token:
            risky_forms.append({
                "page": page,
                "action": form.get("action"),
                "method": method.upper(),
            })

    if risky_forms and cookie_count:
        findings.append({
            "vulnerability": "CSRF",
            "severity": "Medium",
            "details": [f"{item['method']} form on {item['page']} has no obvious CSRF token" for item in risky_forms[:10]],
            "forms": risky_forms,
        })

    return {
        "status": "Potential CSRF risk detected" if risky_forms and cookie_count else "No obvious CSRF risk detected in discovered forms",
        "post_forms_without_token": risky_forms,
        "cookies_observed": cookie_count,
        "note": "This is token-presence analysis, not full CSRF exploit validation.",
    }
