"""
CORS Security Analyzer.

Inspects Cross-Origin Resource Sharing (CORS) headers on the target URL
by sending HTTP requests with a crafted Origin header and examining
what the server reflects back.

Tests performed:
  1. Wildcard origin        — Access-Control-Allow-Origin: *
  2. Wildcard + credentials — * combined with Access-Control-Allow-Credentials: true (broken config)
  3. Origin reflection      — server mirrors back whatever Origin we send
  4. Null origin            — server accepts Origin: null (exploitable via sandboxed iframes)
  5. Subdomain wildcard     — server accepts arbitrary subdomains of the target
  6. Trusted third-party    — server accepts unrelated external origins
  7. Missing CORS headers   — no CORS policy defined at all

Each detected issue includes:
  - issue_type        : machine-readable label
  - description       : plain English explanation of what was detected
  - severity          : Critical / High / Medium / Low
  - evidence          : the actual header values that triggered the finding
  - remediation       : concrete fix recommendation

Findings are appended to the shared findings list using the same
structure as every other scanner module.
"""

import urllib.request
import urllib.error
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Test origins we probe with
# ---------------------------------------------------------------------------

def _build_test_origins(target_origin: str) -> dict:
    """
    Return a labelled dict of Origin header values to test.
    Built dynamically so subdomain tests are relative to the real target.
    """
    parsed = urlparse(target_origin)
    host   = parsed.netloc  # e.g. example.com or api.example.com

    # Strip port if present, grab base domain for subdomain test
    hostname_without_port = host.split(":")[0]
    parts = hostname_without_port.split(".")
    base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname_without_port

    return {
        "attacker_dot_com":          "https://attacker.com",
        "null_origin":               "null",
        "attacker_subdomain":        f"https://evil.{base_domain}",
        "prefixed_target_domain":    f"https://{hostname_without_port}.attacker.com",
        "trusted_third_party":       "https://trusted-partner.example.com",
    }


# ---------------------------------------------------------------------------
# Single CORS probe — send one request with a specific Origin header
# ---------------------------------------------------------------------------

def _send_cors_probe_request(url: str, origin_header_value: str,
                              timeout: int = 10) -> dict:
    """
    Send a GET request with the given Origin header value.
    Returns a dict of the CORS-relevant response headers (lowercased keys).
    Returns an empty dict if the request fails.
    """
    cors_relevant_headers = [
        "access-control-allow-origin",
        "access-control-allow-credentials",
        "access-control-allow-methods",
        "access-control-allow-headers",
        "access-control-expose-headers",
        "access-control-max-age",
        "vary",
    ]

    try:
        request = urllib.request.Request(
            url,
            method="GET",
            headers={
                "Origin":     origin_header_value,
                "User-Agent": "SecurityTestingPlatform/1.0",
                "Accept":     "*/*",
            },
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return {
                header: response.headers.get(header, "")
                for header in cors_relevant_headers
            }

    except urllib.error.HTTPError as http_error:
        # Still capture headers even on 4xx/5xx — CORS headers can appear there
        return {
            header: http_error.headers.get(header, "")
            for header in cors_relevant_headers
        }

    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Individual CORS issue detectors
# ---------------------------------------------------------------------------

def _detect_wildcard_origin(acao_header: str) -> bool:
    """Access-Control-Allow-Origin: * — any origin can read the response."""
    return acao_header.strip() == "*"


def _detect_wildcard_with_credentials(acao_header: str,
                                       acac_header: str) -> bool:
    """
    Wildcard origin combined with Allow-Credentials: true is a broken
    browser configuration — browsers block it, but it signals a
    misconfigured CORS policy that may work in non-browser clients.
    """
    return (
        acao_header.strip() == "*"
        and acac_header.strip().lower() == "true"
    )


def _detect_origin_reflection(acao_header: str,
                               sent_origin: str) -> bool:
    """
    Server blindly reflects back whatever Origin we sent.
    When combined with Allow-Credentials: true this is Critical.
    """
    return (
        acao_header.strip() == sent_origin
        and sent_origin not in ("", "*", "null")
    )


def _detect_null_origin_acceptance(acao_header: str) -> bool:
    """
    Server accepts Origin: null — exploitable via sandboxed iframes,
    data: URIs, and some redirect chains.
    """
    return acao_header.strip().lower() == "null"


def _detect_credentials_with_reflected_origin(acao_header: str,
                                               acac_header: str,
                                               sent_origin: str) -> bool:
    """
    The most dangerous combination: server reflects the attacker origin
    AND signals that cookies/auth headers should be included.
    """
    return (
        _detect_origin_reflection(acao_header, sent_origin)
        and acac_header.strip().lower() == "true"
    )


# ---------------------------------------------------------------------------
# Main analyzer — public API
# ---------------------------------------------------------------------------

def analyze_cors_security(target_url: str, findings: list,
                           timeout: int = 10) -> dict:
    """
    Run all CORS security checks against target_url.

    Args:
        target_url : the URL to test (typically the scan's start URL)
        findings   : shared findings list — issues appended in-place
        timeout    : per-request timeout in seconds

    Returns:
        A cors_analysis dict containing:
          - tested_url
          - test_results  : raw header data per probe origin
          - issues        : list of detected CORS issues with severity + remediation
    """
    parsed        = urlparse(target_url)
    target_origin = f"{parsed.scheme}://{parsed.netloc}"
    test_origins  = _build_test_origins(target_origin)

    print(f"\n🔍 Analyzing CORS security on {target_url}...")

    cors_analysis = {
        "tested_url":   target_url,
        "test_results": {},
        "issues":       [],
    }

    detected_issues = []

    # ── Step 1: Probe with no Origin to get the baseline headers ──
    baseline_headers = _send_cors_probe_request(target_url, target_origin, timeout)
    acao_baseline    = baseline_headers.get("access-control-allow-origin", "")
    acac_baseline    = baseline_headers.get("access-control-allow-credentials", "")

    cors_analysis["test_results"]["same_origin_baseline"] = baseline_headers

    # ── Step 2: Check wildcard on baseline ────────────────────────
    if _detect_wildcard_origin(acao_baseline):
        issue = {
            "issue_type":   "wildcard_origin",
            "description":  "Access-Control-Allow-Origin is set to '*', allowing any website to read responses from this server.",
            "severity":     "High",
            "evidence":     {
                "access-control-allow-origin": acao_baseline,
            },
            "remediation":  "Replace '*' with an explicit allowlist of trusted origins. Never use '*' on endpoints that return sensitive data.",
        }
        detected_issues.append(issue)
        print(f"   🟠 [High]     Wildcard ACAO header detected: *")

        if _detect_wildcard_with_credentials(acao_baseline, acac_baseline):
            issue_broken = {
                "issue_type":   "wildcard_with_credentials",
                "description":  "Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true is an invalid/broken configuration. Browsers block it, but non-browser clients and future spec changes may not.",
                "severity":     "Medium",
                "evidence":     {
                    "access-control-allow-origin":      acao_baseline,
                    "access-control-allow-credentials": acac_baseline,
                },
                "remediation":  "Remove the wildcard. Specify an explicit origin if credentials must be shared. These two headers cannot be used together per the CORS spec.",
            }
            detected_issues.append(issue_broken)
            print(f"   🟡 [Medium]   Wildcard ACAO + credentials flag (broken config)")

    # ── Step 3: Probe with each test origin ───────────────────────
    for origin_label, origin_value in test_origins.items():
        response_headers = _send_cors_probe_request(target_url, origin_value, timeout)
        cors_analysis["test_results"][origin_label] = response_headers

        acao = response_headers.get("access-control-allow-origin", "")
        acac = response_headers.get("access-control-allow-credentials", "")

        # Null origin acceptance
        if origin_value == "null" and _detect_null_origin_acceptance(acao):
            issue = {
                "issue_type":   "null_origin_accepted",
                "description":  "The server accepts 'Origin: null', which can be sent by sandboxed iframes, data: URIs, and local files. Attackers can exploit this to bypass CORS in certain browser contexts.",
                "severity":     "High",
                "evidence":     {
                    "sent_origin":                    origin_value,
                    "access-control-allow-origin":    acao,
                    "access-control-allow-credentials": acac,
                },
                "remediation":  "Remove 'null' from the allowed origins list. Treat null origin the same as an unknown origin.",
            }
            detected_issues.append(issue)
            print(f"   🟠 [High]     Null origin accepted")
            continue

        # Reflected origin (check credentials separately for severity)
        if _detect_origin_reflection(acao, origin_value):
            if _detect_credentials_with_reflected_origin(acao, acac, origin_value):
                issue = {
                    "issue_type":   "origin_reflection_with_credentials",
                    "description":  f"The server reflects the attacker-controlled origin '{origin_value}' back in ACAO AND sets Allow-Credentials: true. This allows a malicious site to make authenticated cross-origin requests and read the response — a complete CORS bypass.",
                    "severity":     "Critical",
                    "evidence":     {
                        "sent_origin":                      origin_value,
                        "access-control-allow-origin":      acao,
                        "access-control-allow-credentials": acac,
                    },
                    "remediation":  "Validate the Origin header against a strict server-side allowlist. Never reflect an unvalidated Origin back in the response header.",
                }
                detected_issues.append(issue)
                print(f"   🔴 [Critical] Origin reflected with credentials — {origin_label}: {origin_value}")
            else:
                issue = {
                    "issue_type":   "origin_reflection_without_credentials",
                    "description":  f"The server reflects the attacker-controlled origin '{origin_value}' in ACAO without credentials. Simple (non-credentialed) cross-origin reads are permitted from any reflected origin.",
                    "severity":     "Medium",
                    "evidence":     {
                        "sent_origin":                    origin_value,
                        "access-control-allow-origin":    acao,
                        "access-control-allow-credentials": acac,
                    },
                    "remediation":  "Validate Origin against an explicit allowlist. Do not reflect the incoming Origin header without validation.",
                }
                detected_issues.append(issue)
                print(f"   🟡 [Medium]   Origin reflected (no credentials) — {origin_label}: {origin_value}")

    # ── Step 4: Check if CORS is entirely absent ──────────────────
    has_any_cors_header = bool(acao_baseline) or any(
        result.get("access-control-allow-origin", "")
        for result in cors_analysis["test_results"].values()
    )

    if not has_any_cors_header:
        issue = {
            "issue_type":   "no_cors_policy_defined",
            "description":  "No CORS headers were detected. While this defaults to same-origin restriction (safe for browsers), it may indicate CORS is not intentionally configured. APIs consumed by external clients will silently fail.",
            "severity":     "Low",
            "evidence":     {
                "access-control-allow-origin": "(not present)"
            },
            "remediation":  "If this endpoint is intended for cross-origin access, define an explicit CORS policy. If it is internal-only, document this as intentional.",
        }
        detected_issues.append(issue)
        print(f"   🟢 [Low]      No CORS policy defined on this endpoint")

    # ── Step 5: Deduplicate and store issues ──────────────────────
    # Use issue_type as dedup key — same issue detected from multiple
    # probe origins should only appear once in the final list
    seen_issue_types   = set()
    deduplicated_issues = []
    for issue in detected_issues:
        if issue["issue_type"] not in seen_issue_types:
            seen_issue_types.add(issue["issue_type"])
            deduplicated_issues.append(issue)

    cors_analysis["issues"] = deduplicated_issues

    print(f"✅ CORS analysis complete — {len(deduplicated_issues)} issue(s) found")

    # ── Step 6: Append to shared findings ─────────────────────────
    # Map CORS issue severity to findings, grouped by severity level
    severity_order = ("Critical", "High", "Medium", "Low")
    for severity_level in severity_order:
        level_issues = [
            issue for issue in deduplicated_issues
            if issue["severity"] == severity_level
        ]
        if not level_issues:
            continue

        findings.append({
            "vulnerability": "CORS Misconfiguration",
            "severity":      severity_level,
            "details": [
                issue["description"] for issue in level_issues
            ],
            "remediation": [
                issue["remediation"] for issue in level_issues
            ],
            "cors_issues": level_issues,
        })

    return cors_analysis
