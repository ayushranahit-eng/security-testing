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
