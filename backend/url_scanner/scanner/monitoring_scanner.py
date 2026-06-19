"""
Baseline-driven monitoring checks for repeat public scans.
"""


def scan_ssl_expiry_monitor(ssl_info: dict, previous_baseline: dict, findings: list, cfg: dict) -> dict:
    days_remaining = ssl_info.get("days_remaining")
    threshold = int(cfg.get("ssl_monitor_days_threshold", 45))
    previous_expiry = previous_baseline.get("ssl_expires")
    current_expiry = ssl_info.get("expires")

    if ssl_info.get("valid") and isinstance(days_remaining, int) and days_remaining <= threshold:
        findings.append({
            "vulnerability": "SSL Certificate Expiry Monitor",
            "severity": "Medium" if days_remaining <= 14 else "Low",
            "details": [f"Certificate expires in {days_remaining} day(s)"],
            "days_remaining": days_remaining,
        })

    return {
        "status": (
            "Certificate renewal threshold reached"
            if ssl_info.get("valid") and isinstance(days_remaining, int) and days_remaining <= threshold
            else "Certificate expiry threshold not reached"
        ),
        "days_remaining": days_remaining,
        "threshold_days": threshold,
        "previous_expiry": previous_expiry,
        "current_expiry": current_expiry,
        "baseline_changed": bool(previous_expiry and current_expiry and previous_expiry != current_expiry),
    }


def scan_security_header_regression(current_headers: dict, previous_baseline: dict, findings: list) -> dict:
    previous_present = set(previous_baseline.get("present_headers", []))
    current_present = set(current_headers.get("present", []))
    regressed = sorted(previous_present - current_present)

    if previous_present and regressed:
        findings.append({
            "vulnerability": "Security Header Regression Alert",
            "severity": "Medium",
            "details": [f"Previously present header now missing: {header}" for header in regressed],
            "headers": regressed,
        })

    return {
        "status": "Header regression detected" if previous_present and regressed else "No header regression detected",
        "regressed_headers": regressed,
        "previous_baseline_available": bool(previous_present),
    }


def scan_exposed_asset_drift(current_pages: list, current_api_calls: list, previous_baseline: dict, findings: list) -> dict:
    previous_pages = set(previous_baseline.get("pages", []))
    previous_api_calls = set(previous_baseline.get("api_calls", []))
    current_page_set = set(current_pages)
    current_api_set = set(current_api_calls)

    new_pages = sorted(current_page_set - previous_pages)
    new_api_calls = sorted(current_api_set - previous_api_calls)
    removed_pages = sorted(previous_pages - current_page_set)
    removed_api_calls = sorted(previous_api_calls - current_api_set)

    if (previous_pages or previous_api_calls) and (new_pages or new_api_calls or removed_pages or removed_api_calls):
        findings.append({
            "vulnerability": "Exposed Asset Drift Detection",
            "severity": "Low" if len(new_api_calls) + len(new_pages) <= 5 else "Medium",
            "details": (
                [f"New page exposed: {item}" for item in new_pages[:10]]
                + [f"New API call observed: {item}" for item in new_api_calls[:10]]
                + [f"Previously seen page missing: {item}" for item in removed_pages[:10]]
                + [f"Previously seen API call missing: {item}" for item in removed_api_calls[:10]]
            ),
            "new_pages": new_pages,
            "new_api_calls": new_api_calls,
            "removed_pages": removed_pages,
            "removed_api_calls": removed_api_calls,
        })

    return {
        "status": "Asset drift detected" if (previous_pages or previous_api_calls) and (new_pages or new_api_calls or removed_pages or removed_api_calls) else "No exposed asset drift detected",
        "new_pages": new_pages,
        "new_api_calls": new_api_calls,
        "removed_pages": removed_pages,
        "removed_api_calls": removed_api_calls,
        "previous_baseline_available": bool(previous_pages or previous_api_calls),
    }
