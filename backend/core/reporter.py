"""
Report generator.

The scanner collects a lot of raw evidence. This module turns that evidence
into a tighter engineer-readable report: priority, impact, confidence,
evidence, and concrete remediation.
"""

from html import unescape
from urllib.parse import urlparse


SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
STATIC_EXTENSIONS = {
    ".css", ".js", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp",
    ".ico", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".mp4",
    ".webm", ".pdf", ".txt", ".xml",
}
PAGE_EXTENSIONS = {".html", ".htm", ".php", ".asp", ".aspx", ".jsp"}
TRACKING_HOST_KEYWORDS = {
    "google-analytics", "googletagmanager", "googleadservices", "doubleclick",
    "facebook", "hotjar", "clarity", "segment", "mixpanel", "gstatic",
    "googleapis", "cloudflareinsights",
}
THIRD_PARTY_SERVICE_KEYWORDS = {"tawk", "recaptcha", "captcha", "stripe", "paypal"}
TRACKING_COOKIE_PREFIXES = (
    "_ga", "_gid", "_gcl", "_fbp", "_gat", "test_cookie",
    "twk_", "tawk", "Tawk",
)


def generate_readable_json(data: dict, scan_time: str) -> dict:
    target_url = data.get("target", "")
    findings = data.get("findings", [])
    api_analysis = _classify_network_calls(target_url, data.get("api_calls", []))
    sensitive_analysis = _analyze_sensitive_paths(data.get("sensitive_paths", []))
    cookie_analysis = _analyze_cookies(data.get("cookies", []))
    finding_analysis = _analyze_findings(findings)
    counts = _severity_counts(finding_analysis["findings"])

    return {
        "scan_metadata": {
            "target": target_url,
            "scan_completed_at": scan_time,
            "status": "completed",
        },
        "executive_summary": {
            "risk_rating": _overall_risk(counts, sensitive_analysis),
            "scope": {
                "pages_crawled": len(_unique_clean(data.get("pages", []))),
                "forms_discovered": len(data.get("forms", [])),
                "input_fields_found": len(data.get("inputs", [])),
                "buttons_observed": len(data.get("buttons", [])),
                "network_requests_captured": len(data.get("api_calls", [])),
                "cookies_analyzed": len(data.get("cookies", [])),
            },
            "finding_counts": counts,
            "top_risks": finding_analysis["top_risks"],
            "summary": _executive_summary_text(counts, sensitive_analysis, cookie_analysis),
        },
        "attack_surface_analysis": {
            "pages": {
                "count": len(_unique_clean(data.get("pages", []))),
                "note": "Page URLs are counted but not listed in the business report to avoid noisy file-path dumps.",
            },
            "inputs": _summarize_inputs(data.get("inputs", [])),
            "network": api_analysis,
        },
        "security_analysis": {
            "headers": _analyze_headers(data.get("security_headers", {})),
            "ssl": _analyze_ssl(data.get("ssl", {})),
            "cookies": cookie_analysis,
            "sensitive_paths": sensitive_analysis,
            "cors": _analyze_cors_for_readable_report(data.get("cors_analysis", {})),
        },
        "findings": finding_analysis["findings"],
        "recommended_actions": _generate_next_steps(findings, data, api_analysis, sensitive_analysis),
        "raw_data": {
            "note": "Raw scanner output is included for automation and deep review.",
            "complete_scan_results": data,
        },
    }


def generate_text_report(data: dict, scan_time: str) -> str:
    target_url = data.get("target", "")
    findings = data.get("findings", [])
    api_analysis = _classify_network_calls(target_url, data.get("api_calls", []))
    sensitive_analysis = _analyze_sensitive_paths(data.get("sensitive_paths", []))
    cookie_analysis = _analyze_cookies(data.get("cookies", []))
    input_summary = _summarize_inputs(data.get("inputs", []))
    analyzed_findings = _analyze_findings(findings)["findings"]
    counts = _severity_counts(analyzed_findings)

    sep = "=" * 72
    sep2 = "-" * 72
    lines = []
    add = lines.append

    add(sep)
    add("SECURITY SCAN REPORT")
    add(sep)
    add(f"Target    : {target_url}")
    add(f"Scan Date : {scan_time}")
    add("")

    add("EXECUTIVE SUMMARY")
    add(sep2)
    add(f"Overall Risk : {_overall_risk(counts, sensitive_analysis)}")
    add(f"Findings     : {len(analyzed_findings)} total "
        f"({counts['Critical']} Critical, {counts['High']} High, "
        f"{counts['Medium']} Medium, {counts['Low']} Low)")
    add(f"Scope        : {len(_unique_clean(data.get('pages', [])))} pages, "
        f"{len(data.get('forms', []))} forms, {len(data.get('inputs', []))} inputs, "
        f"{len(data.get('api_calls', []))} network requests")
    add("")
    for line in _wrap(_executive_summary_text(counts, sensitive_analysis, cookie_analysis), 70):
        add(line)
    add("")

    add("TOP PRIORITIES")
    add(sep2)
    if not analyzed_findings:
        add("No actionable findings were detected.")
    else:
        for idx, finding in enumerate(analyzed_findings[:5], 1):
            add(f"{idx}. [{finding['severity']}] {finding['title']}")
            add(f"   Priority   : {finding['priority']}")
            add(f"   Confidence : {finding['confidence']}")
            add(f"   Impact     : {finding['impact']}")
            add(f"   Fix        : {finding['remediation']}")
            add("")

    add("ATTACK SURFACE")
    add(sep2)
    add(f"Pages crawled        : {len(_unique_clean(data.get('pages', [])))}")
    add(f"Forms discovered     : {len(data.get('forms', []))}")
    add(f"Input fields         : {input_summary['total']} total")
    add(f"Required inputs      : {input_summary['required_inputs']}")
    add(f"File inputs          : {input_summary['file_inputs']}")
    add(f"Hidden inputs        : {input_summary['hidden_inputs']}")
    add("")
    add("Input types:")
    for input_type, count in input_summary["by_type"].items():
        add(f"  - {input_type}: {count}")
    add("")

    add("NETWORK REQUEST ANALYSIS")
    add(sep2)
    add(f"Captured requests    : {api_analysis['total']}")
    add(f"First-party pages    : {api_analysis['counts']['first_party_pages']}")
    add(f"First-party API-like : {api_analysis['counts']['first_party_api']}")
    add(f"First-party static   : {api_analysis['counts']['first_party_static']}")
    add(f"Third-party services : {api_analysis['counts']['third_party_service']}")
    add(f"Tracking/analytics   : {api_analysis['counts']['tracking_or_analytics']}")
    add(f"Other third-party    : {api_analysis['counts']['other_third_party']}")
    add("")
    if api_analysis["first_party_api"]:
        add("First-party API-like samples:")
        for call in api_analysis["first_party_api"][:10]:
            add(f"  - {call}")
    else:
        add("No clear first-party API endpoints were separated from static/third-party traffic.")
    add("")

    add("SECURITY CONTROLS")
    add(sep2)
    headers = _analyze_headers(data.get("security_headers", {}))
    add(f"Headers : {headers['status']}")
    for item in headers["missing"]:
        add(f"  - Missing {item['header']}: {item['impact']}")
    ssl = _analyze_ssl(data.get("ssl", {}))
    add(f"SSL     : {ssl['status']} ({ssl['note']})")
    add(f"Cookies : {cookie_analysis['status']}")
    for item in cookie_analysis["notable_cookies"][:8]:
        add(f"  - {item['name']} [{item['category']}]: {item['risk']} - {item['issue_summary']}")
    add("")

    add("SENSITIVE PATH ANALYSIS")
    add(sep2)
    add(f"Paths probed         : {sensitive_analysis['paths_probed']}")
    add(f"Exposed/readable     : {len(sensitive_analysis['exposed_paths'])}")
    add(f"Blocked/detected     : {len(sensitive_analysis['blocked_paths'])}")
    add("")
    if sensitive_analysis["exposed_paths"]:
        add("Readable paths needing review:")
        for path in sensitive_analysis["exposed_paths"][:10]:
            add(f"  - [{path['severity']}] {path['path']} "
                f"(HTTP {path['http_status']}, {path['content_type']}, {path['response_size_bytes']}B)")
    if sensitive_analysis["blocked_paths"]:
        add("Blocked paths detected, not confirmed exposed:")
        for path in sensitive_analysis["blocked_paths"][:10]:
            add(f"  - [{path['severity']}] {path['path']} (HTTP {path['http_status']})")
    if not sensitive_analysis["exposed_paths"] and not sensitive_analysis["blocked_paths"]:
        add("No sensitive paths were exposed or detected.")
    add("")

    add("CORS ANALYSIS")
    add(sep2)
    cors = _analyze_cors_for_readable_report(data.get("cors_analysis", {}))
    add(f"Status : {cors['status']}")
    add(f"Note   : {cors['engineer_summary']}")
    for issue in cors.get("issues", []):
        add(f"  - [{issue['severity']}] {issue['issue_type']}: {issue['description']}")
    add("")

    add("FINDINGS DETAIL")
    add(sep2)
    if not analyzed_findings:
        add("No actionable findings were detected.")
    else:
        for idx, finding in enumerate(analyzed_findings, 1):
            add(f"{idx}. [{finding['severity']}] {finding['title']}")
            add(f"   Confidence : {finding['confidence']}")
            add(f"   Impact     : {finding['impact']}")
            add(f"   Evidence   : {finding['evidence_summary']}")
            add(f"   Remediate  : {finding['remediation']}")
            add("")

    add("RECOMMENDED NEXT STEPS")
    add(sep2)
    steps = _generate_next_steps(findings, data, api_analysis, sensitive_analysis)
    for step in steps["priority_order"]:
        add(f"- {step}")
    add("")
    add(sep)
    add("END OF REPORT")
    add(sep)

    return "\n".join(lines)


def _severity_counts(findings: list) -> dict:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for finding in findings:
        severity = finding.get("severity", "Info")
        counts[severity if severity in counts else "Info"] += 1
    return counts


def _overall_risk(counts: dict, sensitive_analysis: dict) -> str:
    if counts["Critical"] or sensitive_analysis.get("critical_exposure_count", 0):
        return "Critical"
    if counts["High"] or sensitive_analysis.get("high_exposure_count", 0):
        return "High"
    if counts["Medium"]:
        return "Medium"
    if counts["Low"]:
        return "Low"
    return "Informational"


def _executive_summary_text(counts: dict, sensitive_analysis: dict, cookie_analysis: dict) -> str:
    exposed = len(sensitive_analysis.get("exposed_paths", []))
    blocked = len(sensitive_analysis.get("blocked_paths", []))
    cookie_issues = len(cookie_analysis.get("notable_cookies", []))

    parts = []
    if exposed:
        parts.append(
            f"{exposed} sensitive path(s) returned readable content. These should be reviewed first because they may expose configuration, dependency, or application metadata."
        )
    if blocked:
        parts.append(
            f"{blocked} sensitive path(s) returned blocked responses. Treat these as detection signals, not confirmed exposure."
        )
    if counts["Medium"] or counts["High"] or counts["Critical"]:
        parts.append(
            "The scanner found issues that should be remediated, but exploitability depends on application context and manual validation."
        )
    if cookie_issues:
        parts.append(
            "Cookie issues were detected; third-party marketing cookies should be separated from true authentication/session cookies during triage."
        )
    if not parts:
        parts.append("No major automated findings were detected in the current unauthenticated scan.")
    return " ".join(parts)


def _unique_clean(values: list) -> list:
    cleaned = []
    seen = set()
    for value in values:
        item = str(value).strip()
        if item and item not in seen:
            seen.add(item)
            cleaned.append(item)
    return cleaned


def _classify_network_calls(target_url: str, calls: list) -> dict:
    target_host = urlparse(target_url).netloc.lower()
    buckets = {
        "first_party_pages": [],
        "first_party_api": [],
        "first_party_static": [],
        "third_party_service": [],
        "tracking_or_analytics": [],
        "other_third_party": [],
    }

    for raw_call in _unique_clean([unescape(str(c)) for c in calls]):
        parsed = urlparse(raw_call)
        host = parsed.netloc.lower()
        path = parsed.path.lower()
        ext = _extension(path)
        is_first_party = host == target_host or host.endswith("." + target_host)

        if any(keyword in host for keyword in TRACKING_HOST_KEYWORDS):
            buckets["tracking_or_analytics"].append(raw_call)
        elif any(keyword in host for keyword in THIRD_PARTY_SERVICE_KEYWORDS):
            buckets["third_party_service"].append(raw_call)
        elif is_first_party and (ext in STATIC_EXTENSIONS or "/assets/" in path or "/static/" in path):
            buckets["first_party_static"].append(raw_call)
        elif is_first_party and (ext in PAGE_EXTENSIONS or ext == ""):
            buckets["first_party_pages"].append(raw_call)
        elif is_first_party:
            buckets["first_party_api"].append(raw_call)
        else:
            buckets["other_third_party"].append(raw_call)

    return {
        "total": sum(len(v) for v in buckets.values()),
        "counts": {key: len(value) for key, value in buckets.items()},
        **buckets,
        "note": "Classification is URL-based. Confirm true API endpoints manually before testing authorization or rate limits.",
    }


def _extension(path: str) -> str:
    if "." not in path.rsplit("/", 1)[-1]:
        return ""
    return "." + path.rsplit(".", 1)[-1].lower()


def _summarize_inputs(inputs: list) -> dict:
    by_type = {}
    unique_fields = set()
    required = 0
    for inp in inputs:
        input_type = (inp.get("type") or "unknown").lower()
        by_type[input_type] = by_type.get(input_type, 0) + 1
        if inp.get("required"):
            required += 1
        unique_fields.add((inp.get("page"), inp.get("id"), inp.get("name"), input_type))

    return {
        "total": len(inputs),
        "unique_field_signatures": len(unique_fields),
        "required_inputs": required,
        "file_inputs": by_type.get("file", 0),
        "hidden_inputs": by_type.get("hidden", 0),
        "by_type": dict(sorted(by_type.items(), key=lambda item: item[0])),
        "risk_note": "Inputs are discovery evidence. Injection/XSS risk requires active validation, which is not yet performed by this scanner.",
    }


def _analyze_headers(headers: dict) -> dict:
    missing = headers.get("missing", [])
    present = headers.get("present", [])
    impact_map = {
        "content-security-policy": "reduces XSS impact and limits untrusted script execution",
        "x-frame-options": "reduces clickjacking risk",
        "strict-transport-security": "enforces HTTPS after first trusted visit",
        "x-content-type-options": "reduces MIME-sniffing risk",
        "referrer-policy": "limits URL/referrer leakage to third parties",
    }
    return {
        "status": "Missing headers detected" if missing else "All required headers present",
        "present": present,
        "missing": [
            {
                "header": header,
                "impact": impact_map.get(header, "improves browser-side security posture"),
                "remediation": f"Configure the {header} response header at the web server or application layer.",
            }
            for header in missing
        ],
    }


def _analyze_ssl(ssl_info: dict) -> dict:
    if ssl_info.get("valid"):
        days = ssl_info.get("days_remaining", "?")
        if isinstance(days, int) and days < 7:
            status = "Critical - certificate expires very soon"
            note = f"Expires in {days} day(s). Renew immediately."
        elif isinstance(days, int) and days < 30:
            status = "Warning - certificate expires soon"
            note = f"Expires in {days} day(s). Schedule renewal."
        else:
            status = "Valid"
            note = f"Certificate is valid with {days} day(s) remaining."
        return {
            "status": status,
            "valid": True,
            "expires_on": ssl_info.get("expires", "Unknown"),
            "days_remaining": days,
            "note": note,
        }

    return {
        "status": "Invalid",
        "valid": False,
        "error": ssl_info.get("error", "Unknown error"),
        "note": "SSL validation failed. Verify certificate chain, hostname, and expiry.",
    }


def _analyze_cookies(cookies: list) -> dict:
    if not cookies:
        return {
            "status": "No cookies detected",
            "count": 0,
            "notable_cookies": [],
            "note": "Run an authenticated scan if the application uses session cookies after login.",
        }

    notable = []
    for cookie in cookies:
        issues = []
        if not cookie.get("secure"):
            issues.append("missing Secure")
        if not cookie.get("httpOnly"):
            issues.append("missing HttpOnly")
        if not cookie.get("sameSite") or str(cookie.get("sameSite")).lower() == "none":
            issues.append("weak or missing SameSite")

        if not issues:
            continue

        name = cookie.get("name") or "unnamed"
        category = _cookie_category(name)
        risk = "Medium" if category == "possible_session_or_app_cookie" else "Low"
        notable.append({
            "name": name,
            "category": category,
            "risk": risk,
            "secure": bool(cookie.get("secure")),
            "httpOnly": bool(cookie.get("httpOnly")),
            "sameSite": cookie.get("sameSite") or "Not Set",
            "issue_summary": ", ".join(issues),
            "triage_note": (
                "Prioritize if this stores authentication or user session state."
                if risk == "Medium"
                else "Likely third-party or marketing cookie; verify before treating as session risk."
            ),
        })

    return {
        "status": f"{len(notable)} cookie(s) need review" if notable else "Cookies appear properly configured",
        "count": len(cookies),
        "notable_cookies": notable,
        "note": "Cookie risk depends on whether the cookie carries authentication/session state.",
    }


def _cookie_category(name: str) -> str:
    if name.startswith(TRACKING_COOKIE_PREFIXES):
        return "tracking_or_third_party_cookie"
    return "possible_session_or_app_cookie"


def _analyze_sensitive_paths(probe_results: list) -> dict:
    exposed = []
    blocked = []

    for probe in probe_results:
        severity = probe.get("severity")
        status = probe.get("status")
        if severity not in ("Critical", "High", "Medium", "Low"):
            continue

        item = {
            "path": probe.get("path"),
            "full_url": probe.get("url"),
            "http_status": status,
            "content_type": probe.get("content_type") or "unknown",
            "response_size_bytes": probe.get("size"),
            "severity": severity,
            "confidence": "High" if status and status < 400 else "Medium",
            "engineer_note": _get_sensitive_path_note(probe.get("path", ""), status == 403),
        }
        if status and status < 400:
            exposed.append(item)
        elif status == 403:
            blocked.append(item)

    return {
        "status": "Sensitive path exposure found" if exposed else "No readable sensitive path exposure confirmed",
        "paths_probed": len(probe_results),
        "exposed_paths": exposed,
        "blocked_paths": blocked,
        "critical_exposure_count": len([p for p in exposed if p["severity"] == "Critical"]),
        "high_exposure_count": len([p for p in exposed if p["severity"] == "High"]),
        "note": "HTTP 403 is not confirmed exposure; it is a signal that the route exists or is being blocked by the server/CDN.",
    }


def _get_sensitive_path_note(path: str, blocked: bool) -> str:
    path_lower = path.lower()
    if blocked:
        return "The server denied access. Review whether this route should exist publicly, but do not treat it as readable exposure."
    if ".env" in path_lower:
        return "Environment files often contain credentials and API keys."
    if ".git" in path_lower:
        return "Git metadata can expose source history and committed secrets."
    if "composer.json" in path_lower or "package.json" in path_lower:
        return "Dependency metadata can help attackers fingerprint frameworks and vulnerable libraries."
    if "swagger" in path_lower or "openapi" in path_lower:
        return "API documentation can expose endpoints and request shapes."
    if any(token in path_lower for token in ["backup", ".sql", "dump"]):
        return "Backup or database files may contain sensitive application data."
    if "wp-config" in path_lower:
        return "WordPress config files can contain database credentials."
    return "Review the content and restrict access if it exposes internal information."


def _analyze_cors_for_readable_report(cors_analysis: dict) -> dict:
    issues = cors_analysis.get("issues", [])
    if not issues:
        return {
            "status": "No CORS issues detected",
            "tested_url": cors_analysis.get("tested_url"),
            "issues": [],
            "engineer_summary": "No unsafe cross-origin behavior was detected by the automated checks.",
        }

    def _issue_rank(issue):
        return SEVERITY_ORDER.get(issue.get("severity", "Low"), 3)

    worst = min(issues, key=_issue_rank)
    return {
        "status": f"{worst.get('severity', 'Low')} CORS observation",
        "tested_url": cors_analysis.get("tested_url"),
        "issues": [
            {
                "issue_type": issue.get("issue_type"),
                "severity": issue.get("severity"),
                "description": issue.get("description"),
                "evidence": issue.get("evidence", {}),
                "remediation": issue.get("remediation"),
            }
            for issue in issues
        ],
        "engineer_summary": _get_cors_engineer_summary(issues),
    }


def _get_cors_engineer_summary(issues: list) -> str:
    issue_types = {issue.get("issue_type") for issue in issues}
    if "no_cors_policy_defined" in issue_types and len(issues) == 1:
        return (
            "No CORS headers were detected. This is usually safe for browser access because "
            "same-origin restrictions apply, but it should be documented if intentional."
        )
    if any(issue.get("severity") in ("Critical", "High") for issue in issues):
        return "High-risk CORS behavior was detected. Restrict origins to a strict allowlist."
    return "Lower-severity CORS observations were detected. Review policy intent and document allowed origins."


def _analyze_findings(findings: list) -> dict:
    analyzed = [_enrich_finding(finding) for finding in findings]
    analyzed.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 4), f["priority"]))
    return {
        "top_risks": [
            {
                "title": finding["title"],
                "severity": finding["severity"],
                "priority": finding["priority"],
                "impact": finding["impact"],
            }
            for finding in analyzed[:3]
        ],
        "findings": analyzed,
    }


def _enrich_finding(finding: dict) -> dict:
    vuln = finding.get("vulnerability", "Unknown")
    severity = finding.get("severity", "Info")
    details = finding.get("details", [])
    if not isinstance(details, list):
        details = [details] if details else []

    if vuln == "Missing Security Headers":
        adjusted_severity = (
            "Medium"
            if len(details) >= 3 and (
                "content-security-policy" in details
                or "strict-transport-security" in details
            )
            else severity
        )
        return {
            "title": "Missing browser security headers",
            "severity": adjusted_severity,
            "priority": "P2",
            "confidence": "High",
            "impact": "Browsers have fewer built-in protections against XSS impact, clickjacking, MIME sniffing, referrer leakage, and HTTPS downgrade scenarios.",
            "evidence_summary": ", ".join(details) if details else "Required headers were absent from the initial response.",
            "remediation": "Add CSP, X-Frame-Options or frame-ancestors, HSTS, X-Content-Type-Options, and Referrer-Policy at the edge or app server.",
            "raw": finding,
        }

    if "Cookie" in vuln:
        cookie_name = finding.get("cookie", "unknown")
        category = _cookie_category(cookie_name)
        likely_tracking = category == "tracking_or_third_party_cookie"
        return {
            "title": f"Cookie security flags need review: {cookie_name}",
            "severity": "Low" if likely_tracking else severity,
            "priority": "P3" if likely_tracking else "P2",
            "confidence": "Medium",
            "impact": (
                "Likely third-party or marketing cookie. Confirm usage before treating it as session risk."
                if likely_tracking
                else "If this cookie stores session or authentication state, missing flags can increase session theft or CSRF risk."
            ),
            "evidence_summary": ", ".join(details),
            "remediation": "Set Secure, HttpOnly, and an explicit SameSite value for application/session cookies. Triage third-party cookies separately.",
            "raw": finding,
        }

    if "Sensitive Path" in vuln:
        path_entries = finding.get("paths", [])
        exposed = [p for p in path_entries if not p.get("blocked")]
        blocked = [p for p in path_entries if p.get("blocked")]
        return {
            "title": "Sensitive path detected",
            "severity": severity if exposed else "Low",
            "priority": "P1" if exposed and severity in ("Critical", "High") else "P3",
            "confidence": "High" if exposed else "Medium",
            "impact": (
                "Readable sensitive paths can expose credentials, dependency metadata, source control traces, or internal configuration."
                if exposed
                else "Detected paths returned blocked responses. This is not confirmed exposure, but it reveals routes worth reviewing."
            ),
            "evidence_summary": f"{len(exposed)} readable, {len(blocked)} blocked. " + "; ".join(details[:5]),
            "remediation": "Remove public access to sensitive files. For blocked routes, confirm they are intentionally blocked and cannot be bypassed.",
            "raw": finding,
        }

    if "CORS" in vuln:
        return {
            "title": "CORS policy observation",
            "severity": severity,
            "priority": "P1" if severity in ("Critical", "High") else "P4",
            "confidence": "High",
            "impact": "Unsafe CORS can allow malicious websites to read browser-authenticated API responses. Missing CORS alone is usually safe but should be intentional.",
            "evidence_summary": "; ".join(details),
            "remediation": "Use an explicit allowlist of trusted origins and avoid credentials with wildcard or reflected origins.",
            "raw": finding,
        }

    return {
        "title": vuln,
        "severity": severity,
        "priority": "P3",
        "confidence": "Medium",
        "impact": "Review this issue in application context.",
        "evidence_summary": "; ".join(details),
        "remediation": "Validate the evidence and remediate according to internal security standards.",
        "raw": finding,
    }


def _generate_next_steps(findings: list, data: dict, api_analysis: dict, sensitive_analysis: dict) -> dict:
    steps = []
    if sensitive_analysis.get("exposed_paths"):
        steps.append("Review readable sensitive paths first; remove or restrict anything exposing dependency, config, or source metadata.")
    if any(f.get("vulnerability") == "Missing Security Headers" for f in findings):
        steps.append("Implement missing security headers at the web server, CDN, or application middleware layer.")
    if any("Cookie" in f.get("vulnerability", "") for f in findings):
        steps.append("Separate third-party cookies from real auth/session cookies, then harden session cookies with Secure, HttpOnly, and SameSite.")
    if api_analysis["counts"]["first_party_api"]:
        steps.append("Manually test first-party API-like endpoints for authentication, authorization, validation, and rate limiting.")
    if data.get("inputs"):
        steps.append("Run active validation tests for inputs: reflected XSS, SQL injection, file upload abuse, and server-side validation bypass.")
    steps.append("Re-run the scan after fixes and compare the findings count plus exposed path list.")
    return {"priority_order": steps}


def _wrap(text: str, width: int) -> list:
    words = text.split()
    lines = []
    current = ""
    for word in words:
        if len(current) + len(word) + 1 > width:
            if current:
                lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return lines
