"""
Report generator — produces the human-readable text report from scan data.
JSON saving is handled by the FastAPI endpoint (streamed to client).
"""


def generate_readable_json(data: dict, scan_time: str) -> dict:
    """
    Generate a human-readable JSON report with engineer-style commentary.
    This makes the JSON output feel like an engineer is explaining findings.
    """
    target_url = data.get("target", "")
    findings   = data.get("findings", [])
    high   = sum(1 for f in findings if f.get("severity") == "High")
    medium = sum(1 for f in findings if f.get("severity") == "Medium")
    low    = sum(1 for f in findings if f.get("severity") == "Low")
    
    # Build the readable JSON structure
    readable = {
        "scan_metadata": {
            "target": target_url,
            "scan_completed_at": scan_time,
            "status": "✅ Scan Completed Successfully"
        },
        
        "executive_summary": {
            "overview": f"Security testing completed for {target_url}",
            "scope": {
                "pages_crawled": len(data.get("pages", [])),
                "forms_discovered": len(data.get("forms", [])),
                "input_fields_found": len(data.get("inputs", [])),
                "buttons_tested": len(data.get("buttons", [])),
                "api_endpoints_detected": len(data.get("api_calls", [])),
                "cookies_analyzed": len(data.get("cookies", []))
            },
            "findings_summary": {
                "total_findings": len(findings),
                "high_severity": high,
                "medium_severity": medium,
                "low_severity": low,
                "status": "🔴 Critical issues found" if high > 0 else 
                         "🟡 Medium issues found" if medium > 0 else
                         "🟢 Minor issues only" if low > 0 else
                         "✅ No issues detected"
            }
        },
        
        "discovery_phase": {
            "status": "✅ Discovery Complete",
            "pages_discovered": [
                {
                    "url": page,
                    "status": "✓ Crawled and analyzed"
                } for page in data.get("pages", [])
            ],
            "api_endpoints_captured": [
                {
                    "endpoint": call,
                    "status": "📡 Detected during page interaction",
                    "note": "API endpoint discovered - recommend further authentication and authorization testing"
                } for call in data.get("api_calls", [])
            ]
        },
        
        "security_analysis": {
            "http_headers": {
                "status": "❌ Issues Found" if data.get("security_headers", {}).get("missing") else "✅ All Required Headers Present",
                "present_headers": [
                    {
                        "header": h,
                        "status": "✓ PASS",
                        "note": "Security header properly configured"
                    } for h in data.get("security_headers", {}).get("present", [])
                ],
                "missing_headers": [
                    {
                        "header": h,
                        "status": "✗ FAIL",
                        "severity": "Low to Medium",
                        "recommendation": f"Add '{h}' header to improve security posture"
                    } for h in data.get("security_headers", {}).get("missing", [])
                ]
            },
            
            "ssl_certificate": _analyze_ssl(data.get("ssl", {})),
            
            "session_cookies": _analyze_cookies(data.get("cookies", []))
        },
        
        "input_discovery": {
            "status": f"✅ Found {len(data.get('inputs', []))} input fields",
            "note": "All input fields should be tested for injection vulnerabilities, XSS, and proper validation",
            "fields": [
                {
                    "type": inp.get("type", "unknown"),
                    "identifier": inp.get("id") or inp.get("name") or "unnamed",
                    "page": inp.get("page"),
                    "placeholder": inp.get("placeholder") or "—",
                    "required": inp.get("required", False),
                    "security_note": _get_input_security_note(inp.get("type"))
                } for inp in data.get("inputs", [])
            ]
        },
        
        "form_analysis": {
            "status": f"{'✅ Found ' + str(len(data.get('forms', []))) + ' forms' if data.get('forms') else 'ℹ️  No forms detected'}",
            "forms": [
                {
                    "page": form.get("page"),
                    "action": form.get("action") or "—",
                    "method": form.get("method") or "GET",
                    "form_id": form.get("id") or f"form_{form.get('form_no')}",
                    "security_note": _get_form_security_note(form)
                } for form in data.get("forms", [])
            ]
        },
        
        "detailed_findings": [
            {
                "finding_id": i + 1,
                "severity": f.get("severity", "Unknown").upper(),
                "vulnerability_type": f.get("vulnerability", "Unknown"),
                "description": _get_finding_description(f),
                "affected_items": f.get("details", []) if isinstance(f.get("details"), list) else [f.get("details")] if f.get("details") else [],
                "risk_level": _get_risk_description(f.get("severity", "Unknown")),
                "recommendation": _get_recommendation(f),
                "engineer_notes": _get_engineer_notes(f)
            } for i, f in enumerate(findings)
        ],
        
        "sensitive_path_analysis": _analyze_sensitive_paths(data.get("sensitive_paths", [])),

        "cors_security_analysis": _analyze_cors_for_readable_report(data.get("cors_analysis", {})),

        "next_steps": _generate_next_steps(findings, data),
        
        "raw_data": {
            "note": "Complete raw scan data for automated processing",
            "buttons_found": data.get("buttons", []),
            "complete_scan_results": data
        }
    }
    
    return readable


def _analyze_ssl(ssl_info: dict) -> dict:
    """Analyze SSL certificate data with engineer commentary."""
    if ssl_info.get("valid"):
        days = ssl_info.get("days_remaining", "?")
        if isinstance(days, int):
            if days < 7:
                status = "🔴 CRITICAL - Certificate expiring very soon!"
                note = f"SSL certificate expires in {days} days - IMMEDIATE action required"
            elif days < 30:
                status = "🟡 WARNING - Certificate expiring soon"
                note = f"SSL certificate expires in {days} days - plan renewal soon"
            else:
                status = "✅ VALID"
                note = f"SSL certificate is valid and expires in {days} days"
        else:
            status = "✅ VALID"
            note = "SSL certificate is properly configured"
            
        return {
            "status": status,
            "valid": True,
            "expires_on": ssl_info.get("expires", "Unknown"),
            "days_remaining": days,
            "engineer_notes": note
        }
    else:
        return {
            "status": "🔴 INVALID",
            "valid": False,
            "error": ssl_info.get("error", "Unknown error"),
            "engineer_notes": "SSL certificate validation failed - investigate immediately"
        }


def _analyze_cookies(cookies: list) -> dict:
    """Analyze cookies with security assessment."""
    if not cookies:
        return {
            "status": "ℹ️  No cookies detected",
            "count": 0,
            "note": "No session cookies found - may indicate stateless authentication or testing needed with authenticated session"
        }
    
    issues = []
    cookie_details = []
    
    for c in cookies:
        cookie_info = {
            "name": c.get("name", "unnamed"),
            "secure_flag": c.get("secure", False),
            "httponly_flag": c.get("httpOnly", False),
            "samesite": c.get("sameSite") or "Not Set",
            "security_status": "✅ Secure" if (c.get("secure") and c.get("httpOnly")) else "⚠️ Has Issues"
        }
        
        cookie_issues = []
        if not c.get("secure"):
            cookie_issues.append("Missing Secure flag - cookie can be transmitted over HTTP")
        if not c.get("httpOnly"):
            cookie_issues.append("Missing HttpOnly flag - vulnerable to XSS attacks")
        if not c.get("sameSite"):
            cookie_issues.append("Missing SameSite attribute - vulnerable to CSRF attacks")
            
        if cookie_issues:
            cookie_info["issues"] = cookie_issues
            issues.extend(cookie_issues)
        else:
            cookie_info["notes"] = "Cookie properly configured with security flags"
            
        cookie_details.append(cookie_info)
    
    return {
        "status": "⚠️ Issues Found" if issues else "✅ All Secure",
        "count": len(cookies),
        "cookies": cookie_details,
        "overall_assessment": f"Found {len(issues)} security issue(s) across {len(cookies)} cookie(s)" if issues else "All cookies properly secured"
    }


def _get_input_security_note(input_type: str) -> str:
    """Get security notes for different input types."""
    notes = {
        "text": "Test for XSS, SQL injection, and command injection",
        "email": "Validate email format; test for injection in email processing",
        "password": "Ensure proper hashing; test for brute force protection",
        "tel": "Validate phone format; check for SMS/phone-based attacks",
        "url": "Validate URL format; test for SSRF and open redirect",
        "number": "Validate numeric ranges; test for overflow/underflow",
        "date": "Validate date ranges; test for logic bypass",
        "file": "Critical: Test for malicious file upload, size limits, file type validation",
        "checkbox": "Test for value manipulation and unexpected state changes",
        "radio": "Test for value manipulation in option selection",
        "textarea": "Test for XSS, injection, and character limit bypass",
        "hidden": "Critical: Hidden fields are user-controllable - validate server-side"
    }
    return notes.get(input_type, "Standard input validation and injection testing required")


def _get_form_security_note(form: dict) -> str:
    """Get security notes for forms."""
    method = (form.get("method") or "GET").upper()
    action = form.get("action")
    
    notes = []
    if method == "GET":
        notes.append("⚠️ Form uses GET method - sensitive data may be exposed in URL")
    if not action or action == "#":
        notes.append("Form submits to same page - verify CSRF protection")
    else:
        notes.append(f"Form submits to: {action} - verify endpoint authentication")
        
    return " | ".join(notes) if notes else "Standard form - test CSRF protection and input validation"


def _get_finding_description(finding: dict) -> str:
    """Generate detailed description for a finding."""
    vuln = finding.get("vulnerability", "Unknown")
    severity = finding.get("severity", "Unknown")
    
    descriptions = {
        "Missing Security Headers": f"The application is missing critical security headers. This is a {severity} severity issue that could allow various attacks including XSS, clickjacking, and MIME-sniffing attacks.",
        "Insecure Cookie": f"Session cookie is not properly secured. This {severity} severity issue could lead to session hijacking or CSRF attacks.",
        "SSL Certificate": f"SSL certificate validation issue detected. This {severity} severity issue affects the security of encrypted communications."
    }
    
    return descriptions.get(vuln, f"{severity} severity security issue: {vuln}")


def _get_risk_description(severity: str) -> str:
    """Get risk level description."""
    risks = {
        "High": "🔴 HIGH RISK - Immediate action required. This vulnerability could be easily exploited and may lead to significant security breach.",
        "Medium": "🟡 MEDIUM RISK - Should be addressed soon. This vulnerability could be exploited with some effort and may lead to security compromise.",
        "Low": "🟢 LOW RISK - Address when convenient. This issue has minimal direct security impact but should be fixed to improve overall security posture."
    }
    return risks.get(severity, "⚪ Unknown risk level")


def _get_recommendation(finding: dict) -> str:
    """Get specific recommendations for findings."""
    vuln = finding.get("vulnerability", "Unknown")
    
    recommendations = {
        "Missing Security Headers": "Add the missing security headers to your web server or application configuration. For content-security-policy, start with a restrictive policy and gradually relax as needed.",
        "Insecure Cookie": "Update cookie configuration to include Secure, HttpOnly, and SameSite attributes. Ensure all session cookies are transmitted over HTTPS only.",
        "SSL Certificate": "Renew or fix SSL certificate configuration immediately. Ensure certificate is valid, properly configured, and covers all required domains."
    }
    
    return recommendations.get(vuln, "Consult security best practices and remediate according to your security policy.")


def _get_engineer_notes(finding: dict) -> str:
    """Get engineer-style notes for findings."""
    vuln = finding.get("vulnerability", "Unknown")
    severity = finding.get("severity", "Unknown")
    
    if vuln == "Missing Security Headers":
        missing = finding.get("details", [])
        if isinstance(missing, list) and missing:
            return f"During testing, I found {len(missing)} security headers missing: {', '.join(missing)}. While this is {severity} severity, implementing these headers is straightforward and significantly improves security posture."
    
    elif vuln == "Insecure Cookie":
        cookie = finding.get("cookie", "unknown")
        return f"The '{cookie}' cookie lacks proper security attributes. This is a {severity} issue - in production, attackers could potentially intercept or manipulate this cookie."
    
    elif "SSL" in vuln or "Certificate" in vuln:
        days = finding.get("days_remaining")
        if days is not None:
            return f"SSL certificate expires in {days} days. Mark your calendar to renew it well before expiration to avoid service disruption."
    
    return f"This {severity} severity finding should be reviewed by the security team and prioritized according to your risk management process."


def _analyze_sensitive_paths(probe_results: list) -> dict:
    """
    Format sensitive path probe results for the readable JSON report.
    Separates actionable hits (accessible or blocked-but-notable) from
    clean results so the reader only focuses on what matters.
    """
    actionable = [
        p for p in probe_results
        if p.get("severity") not in (None, "none", "Info")
    ]
    clean_count = len(probe_results) - len(actionable)

    if not actionable:
        return {
            "status":      "✅ No sensitive paths exposed",
            "paths_probed": len(probe_results),
            "findings":    [],
            "note":        f"All {len(probe_results)} probed paths returned 404 or were otherwise clean."
        }

    formatted_hits = []
    for probe in actionable:
        blocked = probe.get("blocked", False)
        formatted_hits.append({
            "path":         probe.get("path"),
            "full_url":     probe.get("url"),
            "http_status":  probe.get("status"),
            "content_type": probe.get("content_type") or "unknown",
            "response_size_bytes": probe.get("size"),
            "severity":     probe.get("severity"),
            "accessible":   not blocked,
            "status_label": "BLOCKED — server knows this path exists but denies access" if blocked
                            else "ACCESSIBLE — content is readable",
            "engineer_note": _get_sensitive_path_note(probe.get("path", ""), blocked),
        })

    return {
        "status":         f"⚠️  {len(actionable)} sensitive path(s) detected",
        "paths_probed":   len(probe_results),
        "clean_paths":    clean_count,
        "findings":       formatted_hits,
    }


def _get_sensitive_path_note(path: str, blocked: bool) -> str:
    """Return an engineer-style note for a specific sensitive path hit."""
    path_lower = path.lower()
    if ".env" in path_lower:
        return "Environment file may contain database passwords, API keys, and service credentials. Immediate remediation required."
    if ".git" in path_lower:
        return "Git repository metadata is exposed. Attackers can reconstruct source code and discover secrets committed to version control."
    if "swagger" in path_lower or "openapi" in path_lower:
        return "API specification is publicly accessible. This reveals all endpoints, parameters, and authentication methods to potential attackers."
    if "actuator" in path_lower:
        return "Spring Boot Actuator endpoint is exposed. May leak environment variables, configuration, bean mappings, and heap dumps."
    if "phpinfo" in path_lower:
        return "phpinfo() output reveals server configuration, installed modules, and environment variables."
    if any(x in path_lower for x in ["backup", ".sql", "dump"]):
        return "Database or backup file may be directly downloadable — contains all application data."
    if "wp-config" in path_lower:
        return "WordPress configuration file contains database credentials in plaintext."
    if blocked:
        return "Path is blocked (403) but the server acknowledges it exists. Review access controls and consider removing this path entirely."
    return "Sensitive path is accessible — review what information it exposes and restrict access appropriately."


def _analyze_cors_for_readable_report(cors_analysis: dict) -> dict:
    """
    Format CORS analysis results for the readable JSON report.
    """
    issues = cors_analysis.get("issues", [])

    if not issues:
        return {
            "status": "✅ No CORS issues detected",
            "tested_url": cors_analysis.get("tested_url"),
            "issues": [],
            "note": "CORS policy appears correctly configured or not present (same-origin default applies)."
        }

    severity_priority = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    worst_severity    = min(issues, key=lambda i: severity_priority.get(i.get("severity", "Low"), 3))

    status_labels = {
        "Critical": "🔴 CRITICAL — Immediate action required",
        "High":     "🟠 HIGH — Fix before production deployment",
        "Medium":   "🟡 MEDIUM — Plan remediation",
        "Low":      "🟢 LOW — Review and document",
    }

    return {
        "status":     status_labels.get(worst_severity["severity"], "⚠️  Issues found"),
        "tested_url": cors_analysis.get("tested_url"),
        "issues": [
            {
                "issue_type":   issue.get("issue_type"),
                "severity":     issue.get("severity"),
                "description":  issue.get("description"),
                "evidence":     issue.get("evidence", {}),
                "remediation":  issue.get("remediation"),
            }
            for issue in issues
        ],
        "engineer_summary": _get_cors_engineer_summary(issues),
    }


def _get_cors_engineer_summary(issues: list) -> str:
    """Return a plain-English paragraph summarising the CORS findings."""
    if not issues:
        return "No CORS issues found."

    critical = [i for i in issues if i.get("severity") == "Critical"]
    high     = [i for i in issues if i.get("severity") == "High"]

    if critical:
        return (
            f"Found {len(critical)} critical CORS issue(s). "
            "The server reflects attacker-controlled origins AND allows credentials — "
            "this means a malicious website can make authenticated API requests on behalf of "
            "a logged-in user and read the response. This is a full CORS bypass and requires "
            "immediate remediation."
        )
    if high:
        issue_types = ", ".join(i.get("issue_type", "") for i in high)
        return (
            f"Found {len(high)} high-severity CORS issue(s): {issue_types}. "
            "Cross-origin requests from untrusted origins are being permitted. "
            "Review and restrict the CORS policy to an explicit allowlist of trusted origins."
        )
    return (
        f"Found {len(issues)} lower-severity CORS observation(s). "
        "No critical bypass was detected, but the CORS policy should be reviewed "
        "and tightened to follow the principle of least privilege."
    )


def _generate_next_steps(findings: list, data: dict) -> dict:
    """Generate actionable next steps based on findings."""
    steps = {
        "immediate_actions": [],
        "short_term_actions": [],
        "recommendations": [],
        "testing_notes": []
    }
    
    # Analyze findings
    has_high     = any(f.get("severity") == "High"   for f in findings)
    has_medium   = any(f.get("severity") == "Medium" for f in findings)
    has_missing_headers  = any("Header"      in f.get("vulnerability", "") for f in findings)
    has_cookie_issues    = any("Cookie"      in f.get("vulnerability", "") for f in findings)
    has_ssl_issues       = any("SSL"         in f.get("vulnerability", "") or
                               "Certificate" in f.get("vulnerability", "") for f in findings)
    has_sensitive_paths  = any("Sensitive Path" in f.get("vulnerability", "") for f in findings)
    has_cors_issues      = any("CORS"        in f.get("vulnerability", "") for f in findings)
    
    # Immediate actions
    if has_high:
        steps["immediate_actions"].append("🔴 Address HIGH severity findings immediately")
    if has_ssl_issues:
        steps["immediate_actions"].append("🔒 Verify SSL certificate configuration and renewal timeline")
    if has_sensitive_paths:
        steps["immediate_actions"].append("🗂️  Restrict or remove exposed sensitive paths immediately — check for .env, .git, backup files")
    if has_cors_issues and any(f.get("severity") == "Critical" for f in findings if "CORS" in f.get("vulnerability", "")):
        steps["immediate_actions"].append("🌐 Fix Critical CORS misconfiguration — attackers can make authenticated cross-origin requests")
    if not steps["immediate_actions"]:
        steps["immediate_actions"].append("✅ No immediate critical actions required")
    
    # Short term
    if has_medium:
        steps["short_term_actions"].append("🟡 Plan remediation for MEDIUM severity findings")
    if has_missing_headers:
        steps["short_term_actions"].append("🛡️ Implement missing security headers in web server configuration")
    if has_cookie_issues:
        steps["short_term_actions"].append("🍪 Update cookie security attributes in application code")
    if has_cors_issues:
        steps["short_term_actions"].append("🌐 Review and tighten CORS policy — restrict to an explicit allowlist of trusted origins")
    
    # Recommendations
    steps["recommendations"].append(f"🔍 {len(data.get('inputs', []))} input fields identified - conduct thorough injection and XSS testing")
    if data.get("api_calls"):
        steps["recommendations"].append(f"📡 {len(data.get('api_calls', []))} API endpoints detected - test authentication, authorization, and rate limiting")
    steps["recommendations"].append("🔐 Conduct authenticated session testing if application has user authentication")
    steps["recommendations"].append("📝 Review and validate all form submissions for CSRF protection")
    
    # Testing notes
    steps["testing_notes"].append("✓ Automated security scan completed")
    steps["testing_notes"].append("⚠️ Manual penetration testing recommended for comprehensive security assessment")
    steps["testing_notes"].append("📋 Test with authenticated user sessions to discover additional attack surface")
    steps["testing_notes"].append("🔄 Re-run this scan after implementing fixes to verify remediation")
    
    return steps


def generate_text_report(data: dict, scan_time: str) -> str:
    target_url = data.get("target", "")
    findings   = data.get("findings", [])
    high   = sum(1 for f in findings if f.get("severity") == "High")
    medium = sum(1 for f in findings if f.get("severity") == "Medium")
    low    = sum(1 for f in findings if f.get("severity") == "Low")

    sep  = "=" * 60
    sep2 = "-" * 60
    L    = []
    add  = L.append

    add(sep)
    add("  SECURITY SCAN REPORT")
    add(sep)
    add(f"  Target    : {target_url}")
    add(f"  Scan Date : {scan_time}")
    add(sep)
    add("")

    add("OVERVIEW")
    add(sep2)
    add(f"  Pages Crawled  : {len(data.get('pages', []))}")
    add(f"  Forms Found    : {len(data.get('forms', []))}")
    add(f"  Inputs Found   : {len(data.get('inputs', []))}")
    add(f"  Buttons Found  : {len(data.get('buttons', []))}")
    add(f"  API Calls      : {len(data.get('api_calls', []))}")
    add(f"  Cookies        : {len(data.get('cookies', []))}")
    add("")

    add("PAGES DISCOVERED")
    add(sep2)
    for pg in data.get("pages", []):
        add(f"  • {pg}")
    add("")

    add("API CALLS CAPTURED")
    add(sep2)
    for call in data.get("api_calls", []):
        add(f"  • {call}")
    add("")

    add("SECURITY HEADERS")
    add(sep2)
    for h in data.get("security_headers", {}).get("present", []):
        add(f"  [PASS]  {h}")
    for h in data.get("security_headers", {}).get("missing", []):
        add(f"  [FAIL]  {h}  <-- MISSING")
    add("")

    add("SSL CERTIFICATE")
    add(sep2)
    ssl_info = data.get("ssl", {})
    if ssl_info.get("valid"):
        days   = ssl_info.get("days_remaining", "?")
        status = "WARNING — expiring soon" if isinstance(days, int) and days < 30 else "VALID"
        add(f"  Status  : {status}")
        add(f"  Expires : {ssl_info.get('expires', '?')}")
        add(f"  Days    : {days} days remaining")
    else:
        add(f"  Status  : INVALID")
        add(f"  Error   : {ssl_info.get('error', 'Unknown')}")
    add("")

    add("SESSION COOKIES")
    add(sep2)
    cookies = data.get("cookies", [])
    if not cookies:
        add("  No cookies found.")
    else:
        for c in cookies:
            add(f"  Cookie   : {c.get('name') or 'unnamed'}")
            add(f"    Secure   : {'Yes' if c.get('secure')   else 'No  <-- WEAK'}")
            add(f"    HttpOnly : {'Yes' if c.get('httpOnly') else 'No  <-- WEAK'}")
            add(f"    SameSite : {c.get('sameSite') or 'Not Set'}")
            add("")
    add("")

    add("INPUT FIELDS FOUND")
    add(sep2)
    inputs = data.get("inputs", [])
    if not inputs:
        add("  No input fields found.")
    else:
        for inp in inputs:
            id_   = inp.get("id")          or "—"
            name  = inp.get("name")        or "—"
            type_ = inp.get("type")        or "—"
            ph    = inp.get("placeholder") or "—"
            req   = "required" if inp.get("required") else ""
            pg    = inp.get("page")        or "—"
            add(f"  [{type_:<14}]  id={id_:<28}  name={name:<20}  placeholder={ph:<20}  {req}  ({pg})")
    add("")

    add("SENSITIVE PATH PROBING")
    add(sep2)
    sensitive_paths = data.get("sensitive_paths", [])
    actionable_paths = [
        p for p in sensitive_paths
        if p.get("severity") not in (None, "none", "Info")
    ]
    if not actionable_paths:
        add("  No sensitive paths found or accessible.")
    else:
        for probe in actionable_paths:
            status   = probe.get("status", "?")
            severity = probe.get("severity", "?")
            path     = probe.get("path", "?")
            ct       = probe.get("content_type") or "unknown"
            size     = probe.get("size")
            blocked  = probe.get("blocked", False)
            tag      = "BLOCKED (403)" if blocked else f"ACCESSIBLE ({status})"
            size_str = f"  {size}B" if size is not None else ""
            add(f"  [{severity:<8}]  {path:<40}  {tag}  {ct}{size_str}")
    add("")

    add("CORS SECURITY ANALYSIS")
    add(sep2)
    cors_analysis = data.get("cors_analysis", {})
    cors_issues   = cors_analysis.get("issues", [])
    if not cors_issues:
        add("  No CORS issues detected.")
    else:
        for issue in cors_issues:
            severity    = issue.get("severity", "?")
            issue_type  = issue.get("issue_type", "?")
            description = issue.get("description", "")
            remediation = issue.get("remediation", "")
            evidence    = issue.get("evidence", {})
            add(f"  [{severity:<8}]  {issue_type}")
            add(f"             {description}")
            for header_name, header_value in evidence.items():
                add(f"             Evidence  : {header_name}: {header_value}")
            add(f"             Fix       : {remediation}")
            add("")
    add("")

    add(sep)
    add("  FINDINGS SUMMARY")
    add(sep)
    add(f"  Total   : {len(findings)}")
    add(f"  High    : {high}")
    add(f"  Medium  : {medium}")
    add(f"  Low     : {low}")
    add("")

    if not findings:
        add("  No vulnerabilities found.")
    else:
        for i, f in enumerate(findings, 1):
            add(f"  [{i}] {f.get('severity','?').upper()} — {f.get('vulnerability','?')}")
            details = f.get("details")
            if isinstance(details, list):
                for d in details:
                    add(f"       • {d}")
            elif isinstance(details, str):
                add(f"       {details}")
            if f.get("cookie"):
                add(f"       Cookie: {f['cookie']}")
            if f.get("days_remaining") is not None:
                add(f"       Days remaining: {f['days_remaining']}")
            add("")

    add(sep)
    add("  END OF REPORT")
    add(sep)

    return "\n".join(L)
