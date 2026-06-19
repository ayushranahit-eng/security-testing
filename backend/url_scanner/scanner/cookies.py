"""
Cookie analyser.
Checks Secure, HttpOnly, and SameSite flags.

Cookie findings are intentionally conservative: third-party/marketing cookies
are not the same risk as application session cookies.
"""


TRACKING_COOKIE_PREFIXES = (
    "_ga", "_gid", "_gcl", "_fbp", "_gat", "test_cookie",
    "twk_", "tawk", "Tawk",
)


def _cookie_category(name: str) -> str:
    if (name or "").startswith(TRACKING_COOKIE_PREFIXES):
        return "tracking_or_third_party_cookie"
    return "possible_session_or_app_cookie"


def analyse_cookies(raw_cookies: list, findings: list) -> list:
    """
    Inspect each cookie for weak security flags.
    Appends findings for any issues found.
    Returns cleaned cookie info list.
    """
    result = []

    for cookie in raw_cookies:
        info = {
            "name":     cookie.get("name"),
            "secure":   cookie.get("secure"),
            "httpOnly": cookie.get("httpOnly"),
            "sameSite": cookie.get("sameSite"),
            "domain":   cookie.get("domain"),
            "path":     cookie.get("path"),
            "category": _cookie_category(cookie.get("name") or ""),
        }
        result.append(info)

        issues = []
        if not cookie.get("secure"):
            issues.append("Secure=False")
        if not cookie.get("httpOnly"):
            issues.append("HttpOnly=False")
        if (cookie.get("sameSite") or "").lower() == "none":
            issues.append("SameSite=None")

        if issues:
            category = info["category"]
            findings.append({
                "vulnerability": "Weak Cookie Flags",
                "severity":      "Low" if category == "tracking_or_third_party_cookie" else "Medium",
                "cookie":        cookie.get("name"),
                "category":      category,
                "details":       issues,
            })

    print(f"{len(result)} cookies discovered")
    return result
