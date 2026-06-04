"""
SSL certificate checker.
Connects directly via socket — no browser needed.
"""

import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse


def check_ssl(url: str) -> dict:
    try:
        hostname = urlparse(url).hostname
        ctx = ssl.create_default_context()

        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        expiry = datetime.strptime(
            cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=timezone.utc)

        days_remaining = (expiry - datetime.now(timezone.utc)).days

        print(f"✅ SSL Valid ({days_remaining} days remaining)")

        return {
            "valid":          True,
            "expires":        str(expiry),
            "days_remaining": days_remaining,
        }

    except Exception as e:
        print(f"❌ SSL Certificate Issue: {e}")
        return {"valid": False, "error": str(e)}


def evaluate_ssl(ssl_info: dict, findings: list) -> None:
    """Add a finding if SSL is invalid or expiring soon."""
    if not ssl_info.get("valid"):
        findings.append({
            "vulnerability": "SSL Certificate Issue",
            "severity":      "High",
            "details":       ssl_info.get("error"),
        })
    elif ssl_info.get("days_remaining", 999) < 30:
        findings.append({
            "vulnerability": "SSL Certificate Expiring Soon",
            "severity":      "Medium",
            "days_remaining": ssl_info["days_remaining"],
        })
