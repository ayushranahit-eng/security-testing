"""
Server header disclosure scanner.

Looks for response headers that disclose server-side implementation detail.
"""


DISCLOSURE_HEADERS = {
    "server": "web server banner",
    "x-powered-by": "application runtime disclosure",
    "x-aspnet-version": "ASP.NET version disclosure",
    "x-aspnetmvc-version": "ASP.NET MVC version disclosure",
    "via": "intermediary proxy disclosure",
    "x-generator": "framework or CMS disclosure",
}


def scan_server_header_disclosure(response_headers: dict, findings: list) -> dict:
    normalized = {
        str(key).strip().lower(): str(value).strip()
        for key, value in dict(response_headers or {}).items()
        if str(value or "").strip()
    }
    disclosed = []

    for header_name, description in DISCLOSURE_HEADERS.items():
        value = normalized.get(header_name)
        if not value:
            continue
        disclosed.append({
            "header": header_name,
            "value": value,
            "description": description,
        })

    if disclosed:
        findings.append({
            "vulnerability": "Server Header Disclosure",
            "severity": "Low",
            "details": [
                f"{item['header']}: {item['value']}"
                for item in disclosed
            ],
            "headers": disclosed,
        })

    return {
        "status": "Disclosure headers present" if disclosed else "No notable disclosure headers detected",
        "headers": disclosed,
        "note": "Version banners are not always exploitable on their own, but they make stack profiling easier for attackers.",
    }
