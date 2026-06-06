"""
Default scan configuration.
Every value here can be overridden per-request via the ScanRequest body.
"""

from datetime import datetime

DEFAULT_CONFIG = {
    # Browser
    "headless": True,
    "slow_mo":  0,

    # Timeouts (ms)
    "page_timeout":      30_000,
    "interaction_wait":   2_000,
    "network_idle_wait":  5_000,
    "post_click_wait":    5_000,

    # Crawl limits
    "max_pages": 20,
    "max_depth":  2,

    # JavaScript secret scanning
    "max_javascript_files": 25,
    "max_inline_script_pages": 10,
    "max_download_bytes_per_file": 500_000,

    # Reflected XSS validation
    "xss_marker_prefix": "hitxss",
    "xss_payload_tag": "hit-xss-check",
    "stored_xss_payload_tag": "hit-stored-xss",
    "dom_xss_payload_tag": "hit-dom-xss",

    # Open redirect validation
    "open_redirect_test_url": "https://example.org/hit-open-redirect",
    "open_redirect_parameter_names": [
        "redirect", "redirect_url", "redirect_uri", "next", "return",
        "returnurl", "return_url", "continue", "dest", "destination",
        "url", "callback", "callbackurl", "redir",
    ],

    # SQL injection validation
    "sqli_error_patterns": [
        "sql syntax", "mysql", "warning: mysql", "unclosed quotation mark",
        "quoted string not properly terminated", "postgresql", "pg_query",
        "sqlite error", "sqliteexception", "sqlstate", "odbc sql",
        "microsoft ole db provider for sql server", "ora-01756", "ora-00933",
        "syntax error at or near", "you have an error in your sql syntax",
    ],
    "sqli_test_payloads": [
        "'",
        "\"",
        "' OR '1'='1",
    ],
    "sqli_max_test_parameters": 3,

    # HTTP method and endpoint probing
    "interesting_http_methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"],
    "forced_browsing_paths": [
        "/admin", "/admin/", "/dashboard", "/manage", "/internal", "/console",
        "/staff", "/private", "/dev", "/test", "/debug", "/api/docs",
        "/docs", "/graphql", "/graphiql", "/swagger", "/actuator",
    ],
    "graphql_common_paths": ["/graphql", "/api/graphql", "/query", "/graphiql"],
    "rate_limit_probe_requests": 6,
    "rate_limit_probe_delay_ms": 250,

    # Security headers to verify
    "required_security_headers": [
        "content-security-policy",
        "x-frame-options",
        "strict-transport-security",
        "x-content-type-options",
        "referrer-policy",
    ],

    # Test values injected into form fields
    "test_values": {
        "text":           "Test User",
        "textarea":       "Test content for security scanning",
        "email":          "test@example.com",
        "password":       "Password123!",
        "number":         "10",
        "tel":            "9999999999",
        "search":         "test",
        "date":           datetime.now().strftime("%Y-%m-%d"),
        "datetime-local": datetime.now().strftime("%Y-%m-%dT%H:%M"),
        "url":            "https://example.com",
        "color":          "#ff0000",
        "range":          "5",
        "month":          datetime.now().strftime("%Y-%m"),
        "week":           datetime.now().strftime("%Y-W%W"),
        "time":           "10:00",
    },

    # Buttons whose text contains these words are never clicked
    "always_skip_button_keywords": [
        "delete", "remove", "logout", "log out", "sign out",
        "purchase", "pay", "checkout", "buy", "deactivate",
        "unsubscribe", "wipe", "destroy", "terminate",
    ],
}
