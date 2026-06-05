"""
Session cookie analyser.
Checks Secure, HttpOnly, and SameSite flags.
"""


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
            findings.append({
                "vulnerability": "Weak Session Cookie",
                "severity":      "Medium",
                "cookie":        cookie.get("name"),
                "details":       issues,
            })

    print(f"✅ {len(result)} cookies discovered")
    return result
