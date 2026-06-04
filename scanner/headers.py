"""
Security headers checker.
Runs against the HTTP response from the initial page load.
"""


def check_headers(response_headers: dict, required: list, findings: list) -> dict:
    """
    Compare response headers against the required list.
    Appends a finding if any are missing.
    Returns a dict with 'present' and 'missing' lists.
    """
    present = [h for h in required if h in response_headers]
    missing = [h for h in required if h not in response_headers]

    result = {"present": present, "missing": missing}

    if missing:
        print(f"⚠️  Missing {len(missing)} security headers")
        for h in missing:
            print(f"   ❌ {h}")
        findings.append({
            "vulnerability": "Missing Security Headers",
            "severity":      "Low",
            "details":       missing,
        })
    else:
        print("✅ All security headers present")

    return result
