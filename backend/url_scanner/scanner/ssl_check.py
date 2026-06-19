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
                negotiated_protocol = ssock.version()
                negotiated_cipher = ssock.cipher()

        expiry = datetime.strptime(
            cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=timezone.utc)

        days_remaining = (expiry - datetime.now(timezone.utc)).days
        weak_protocols_supported = _probe_legacy_tls_versions(hostname)
        weak_cipher_suites_accepted = _probe_weak_cipher_support(hostname)

        print(f"✅ SSL Valid ({days_remaining} days remaining)")

        return {
            "valid":          True,
            "expires":        str(expiry),
            "days_remaining": days_remaining,
            "negotiated_protocol": negotiated_protocol,
            "negotiated_cipher": _serialize_cipher(negotiated_cipher),
            "weak_protocols_supported": weak_protocols_supported,
            "weak_cipher_suites_accepted": weak_cipher_suites_accepted,
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

    weak_protocols = ssl_info.get("weak_protocols_supported", [])
    if weak_protocols:
        findings.append({
            "vulnerability": "Weak TLS Protocol Supported",
            "severity": "Medium",
            "details": [f"Server accepted legacy TLS version(s): {', '.join(weak_protocols)}"],
            "protocols": weak_protocols,
        })

    weak_ciphers = ssl_info.get("weak_cipher_suites_accepted", [])
    if weak_ciphers:
        findings.append({
            "vulnerability": "Weak Cipher Suites Accepted",
            "severity": "Medium",
            "details": [f"Server accepted weak cipher suite(s): {', '.join(weak_ciphers)}"],
            "cipher_suites": weak_ciphers,
        })


def _serialize_cipher(cipher: tuple | None) -> dict | None:
    if not cipher:
        return None
    name, protocol, bits = cipher
    return {
        "name": name,
        "protocol": protocol,
        "bits": bits,
    }


def _probe_legacy_tls_versions(hostname: str) -> list[str]:
    supported = []
    version_candidates = [
        ("TLSv1.0", getattr(ssl.TLSVersion, "TLSv1", None)),
        ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
    ]

    for label, tls_version in version_candidates:
        if tls_version is None:
            continue
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = tls_version
            ctx.maximum_version = tls_version
            with socket.create_connection((hostname, 443), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname):
                    supported.append(label)
        except Exception:
            continue

    return supported


def _probe_weak_cipher_support(hostname: str) -> list[str]:
    supported = []
    weak_cipher_candidates = [
        "DES-CBC3-SHA",
        "AES128-SHA",
        "ECDHE-RSA-AES128-SHA",
        "RC4-SHA",
    ]

    for cipher_name in weak_cipher_candidates:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = getattr(ssl.TLSVersion, "TLSv1_2", ssl.TLSVersion.MINIMUM_SUPPORTED)
            ctx.maximum_version = getattr(ssl.TLSVersion, "TLSv1_2", ssl.TLSVersion.MAXIMUM_SUPPORTED)
            ctx.set_ciphers(f"{cipher_name}:@SECLEVEL=0")
            with socket.create_connection((hostname, 443), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname):
                    supported.append(cipher_name)
        except Exception:
            continue

    return supported
