import socket
import ssl
from urllib.parse import urlparse

import dns.resolver
import requests


def normalize_domain(domain: str) -> str:
    """Clean the domain entered by the user."""
    domain = domain.strip()

    if not domain:
        raise ValueError("Domain cannot be empty.")

    if not domain.startswith(("http://", "https://")):
        domain = "https://" + domain

    parsed = urlparse(domain)

    if not parsed.hostname:
        raise ValueError("Invalid domain.")

    return parsed.hostname.lower()


def check_dns(domain: str) -> list[str]:
    """Get IPv4 addresses for the domain."""
    try:
        answers = dns.resolver.resolve(domain, "A")
        return [answer.to_text() for answer in answers]
    except Exception:
        return []


def check_http(domain: str) -> dict:
    """Check HTTPS and common HTTP security headers."""
    result = {
        "https_available": False,
        "status_code": None,
        "final_url": None,
        "security_headers": {},
    }

    try:
        url = f"https://{domain}"

        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={"User-Agent": "CyberShield/1.0"},
        )

        result["https_available"] = True
        result["status_code"] = response.status_code
        result["final_url"] = response.url

        headers_to_check = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Referrer-Policy",
            "Permissions-Policy",
        ]

        for header in headers_to_check:
            result["security_headers"][header] = (
                response.headers.get(header) is not None
            )

    except requests.RequestException:
        pass

    return result


def check_ssl(domain: str) -> dict:
    """Check whether a valid TLS connection can be established."""
    result = {
        "valid_connection": False,
        "issuer": None,
        "subject": None,
    }

    try:
        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                certificate = secure_sock.getpeercert()

                result["valid_connection"] = True

                result["issuer"] = str(certificate.get("issuer"))
                result["subject"] = str(certificate.get("subject"))

    except (socket.timeout, socket.error, ssl.SSLError):
        pass

    return result


def calculate_risk(http_result: dict, ssl_result: dict) -> dict:
    """Create a simple rule-based risk indicator."""
    score = 0
    reasons = []

    if not http_result["https_available"]:
        score += 40
        reasons.append("HTTPS connection could not be established.")

    if not ssl_result["valid_connection"]:
        score += 30
        reasons.append("SSL/TLS connection could not be verified.")

    missing_headers = [
        name
        for name, present in http_result["security_headers"].items()
        if not present
    ]

    if missing_headers:
        score += min(len(missing_headers) * 5, 30)
        reasons.append("Some recommended security headers are missing.")

    if score <= 20:
        level = "Low"
    elif score <= 50:
        level = "Medium"
    else:
        level = "High"

    return {
        "score": score,
        "level": level,
        "reasons": reasons,
    }


def scan_domain(domain: str) -> dict:
    """Run all CyberShield defensive checks."""
    domain = normalize_domain(domain)

    dns_result = check_dns(domain)
    http_result = check_http(domain)
    ssl_result = check_ssl(domain)
    risk_result = calculate_risk(http_result, ssl_result)

    return {
        "domain": domain,
        "dns": {
            "ipv4_addresses": dns_result,
        },
        "http": http_result,
        "ssl": ssl_result,
        "risk": risk_result,
    }