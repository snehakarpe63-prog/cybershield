import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import dns.resolver
import requests


def normalize_domain(domain: str) -> str:
    """Clean and validate the domain entered by the user."""
    domain = domain.strip()

    if not domain:
        raise ValueError("Domain cannot be empty.")

    if not domain.startswith(("http://", "https://")):
        domain = "https://" + domain

    parsed = urlparse(domain)

    if not parsed.hostname:
        raise ValueError("Invalid domain.")

    return parsed.hostname.lower()


def check_dns(domain: str) -> dict:
    """Check basic IPv4 DNS resolution."""
    result = {
        "status": "Unable to verify",
        "ipv4_addresses": [],
    }

    try:
        answers = dns.resolver.resolve(domain, "A")

        addresses = [
            answer.to_text()
            for answer in answers
        ]

        result["status"] = "Verified"
        result["ipv4_addresses"] = addresses

    except Exception:
        pass

    return result


def check_http(domain: str) -> dict:
    """
    Check HTTPS and HTTP separately.

    Security headers are only evaluated when an HTTPS
    response is actually received.
    """

    result = {
        "https": {
            "status": "Unable to verify",
            "reachable": False,
            "status_code": None,
            "final_url": None,
        },
        "http": {
            "status": "Unable to verify",
            "reachable": False,
            "status_code": None,
            "final_url": None,
        },
        "security_headers": {},
    }

    headers_to_check = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    ]

    # -------------------------
    # HTTPS
    # -------------------------

    try:
        response = requests.get(
            f"https://{domain}",
            timeout=10,
            allow_redirects=True,
            headers={
                "User-Agent": "CyberShield/1.0"
            },
        )

        result["https"]["status"] = "Verified"
        result["https"]["reachable"] = True
        result["https"]["status_code"] = response.status_code
        result["https"]["final_url"] = response.url

        for header in headers_to_check:
            result["security_headers"][header] = (
                response.headers.get(header) is not None
            )

    except requests.RequestException:
        pass

    # -------------------------
    # HTTP
    # -------------------------

    try:
        response = requests.get(
            f"http://{domain}",
            timeout=10,
            allow_redirects=True,
            headers={
                "User-Agent": "CyberShield/1.0"
            },
        )

        result["http"]["status"] = "Verified"
        result["http"]["reachable"] = True
        result["http"]["status_code"] = response.status_code
        result["http"]["final_url"] = response.url

    except requests.RequestException:
        pass

    return result


def check_ssl(domain: str) -> dict:
    """Check the TLS certificate."""
    result = {
        "status": "Unable to verify",
        "reachable": False,
        "valid_connection": False,
        "issuer": None,
        "subject": None,
        "expires_at": None,
        "days_until_expiry": None,
    }

    try:
        context = ssl.create_default_context()

        with socket.create_connection(
            (domain, 443),
            timeout=10,
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=domain,
            ) as secure_sock:

                certificate = secure_sock.getpeercert()

                result["reachable"] = True
                result["valid_connection"] = True
                result["status"] = "Verified"

                result["issuer"] = str(
                    certificate.get("issuer")
                )

                result["subject"] = str(
                    certificate.get("subject")
                )

                expiry_string = certificate.get(
                    "notAfter"
                )

                if expiry_string:

                    expiry_timestamp = (
                        ssl.cert_time_to_seconds(
                            expiry_string
                        )
                    )

                    expiry_datetime = (
                        datetime.fromtimestamp(
                            expiry_timestamp,
                            tz=timezone.utc,
                        )
                    )

                    now = datetime.now(timezone.utc)

                    days_remaining = (
                        expiry_datetime - now
                    ).days

                    result["expires_at"] = (
                        expiry_datetime.strftime(
                            "%Y-%m-%d %H:%M:%S UTC"
                        )
                    )

                    result["days_until_expiry"] = (
                        days_remaining
                    )

    except ssl.SSLCertVerificationError:
        result["reachable"] = True
        result["status"] = "Certificate verification failed"

    except (
        socket.timeout,
        socket.error,
        ssl.SSLError,
    ):
        pass

    return result


def calculate_risk(
    http_result: dict,
    ssl_result: dict,
) -> dict:
    """
    Calculate a simple defensive risk indicator.

    The scanner does not treat an inability to verify
    something as a confirmed security weakness.
    """

    score = 0
    findings = []
    limitations = []

    https = http_result["https"]
    http = http_result["http"]

    # -------------------------
    # HTTPS
    # -------------------------

    if not https["reachable"]:

        if http["reachable"]:

            score += 40

            findings.append(
                "The domain responded over HTTP, "
                "but an HTTPS connection could not be established."
            )

        else:

            limitations.append(
                "The scanner could not establish either "
                "an HTTP or HTTPS connection."
            )

    # -------------------------
    # TLS
    # -------------------------

    if ssl_result["valid_connection"]:

        days_remaining = (
            ssl_result["days_until_expiry"]
        )

        if days_remaining is not None:

            if days_remaining < 0:

                score += 40

                findings.append(
                    "The TLS certificate appears to be expired."
                )

            elif days_remaining <= 30:

                score += 15

                findings.append(
                    "The TLS certificate expires within 30 days."
                )

    else:

        if https["reachable"]:

            limitations.append(
                "HTTPS was reachable, but the TLS "
                "certificate could not be fully verified."
            )

    # -------------------------
    # Security headers
    # -------------------------

    headers = http_result["security_headers"]

    if headers:

        missing_headers = [
            name
            for name, present in headers.items()
            if not present
        ]

        if missing_headers:

            score += min(
                len(missing_headers) * 5,
                30,
            )

            findings.append(
                "Some recommended HTTP security "
                "headers are missing."
            )

    else:

        limitations.append(
            "Security headers could not be evaluated "
            "because no HTTPS response headers were obtained."
        )

    # -------------------------
    # Risk level
    # -------------------------

    if score == 0 and limitations:
        level = "Unverified"

    elif score <= 20:
        level = "Low"

    elif score <= 50:
        level = "Medium"

    else:
        level = "High"

    return {
        "score": score,
        "level": level,
        "findings": findings,
        "limitations": limitations,
    }


def scan_domain(domain: str) -> dict:
    """Run all CyberShield defensive checks."""

    domain = normalize_domain(domain)

    dns_result = check_dns(domain)
    http_result = check_http(domain)
    ssl_result = check_ssl(domain)

    risk_result = calculate_risk(
        http_result,
        ssl_result,
    )

    return {
        "domain": domain,
        "dns": dns_result,
        "http": http_result,
        "ssl": ssl_result,
        "risk": risk_result,
    }