def build_recommendations(scan_result):
    """
    Build defensive security recommendations from scan results.
    """

    recommendations = []

    http = scan_result.get("http", {})
    https = http.get("https", {})
    headers = http.get("security_headers", {})
    ssl_result = scan_result.get("ssl", {})
    risk = scan_result.get("risk", {})

    # HTTPS recommendation
    if not https.get("reachable", False):
        recommendations.append({
            "title": "Review HTTPS configuration",
            "why": (
                "CyberShield could not establish an HTTPS connection "
                "to the domain."
            ),
            "action": (
                "Review the domain's HTTPS/TLS configuration and ensure "
                "the service is correctly configured for HTTPS."
            )
        })

    # Security header recommendations
    header_recommendations = {
        "Strict-Transport-Security": {
            "title": "Review Strict-Transport-Security (HSTS)",
            "why": (
                "The Strict-Transport-Security header was not detected "
                "in the HTTPS response."
            ),
            "action": (
                "Review whether HSTS is appropriate for the application "
                "and configure it according to the deployment requirements."
            )
        },

        "Content-Security-Policy": {
            "title": "Review Content-Security-Policy",
            "why": (
                "The Content-Security-Policy header was not detected."
            ),
            "action": (
                "Review the application's resource-loading requirements "
                "and consider implementing an appropriate Content "
                "Security Policy."
            )
        },

        "X-Content-Type-Options": {
            "title": "Review X-Content-Type-Options",
            "why": (
                "The X-Content-Type-Options header was not detected."
            ),
            "action": (
                "Review whether the application should send "
                "X-Content-Type-Options: nosniff."
            )
        },

        "X-Frame-Options": {
            "title": "Review clickjacking protection",
            "why": (
                "The X-Frame-Options header was not detected."
            ),
            "action": (
                "Review whether the application should restrict "
                "embedding and framing of its pages."
            )
        },

        "Referrer-Policy": {
            "title": "Review Referrer-Policy",
            "why": (
                "The Referrer-Policy header was not detected."
            ),
            "action": (
                "Review how much referrer information the application "
                "should expose and configure an appropriate policy."
            )
        },

        "Permissions-Policy": {
            "title": "Review Permissions-Policy",
            "why": (
                "The Permissions-Policy header was not detected."
            ),
            "action": (
                "Review browser features used by the application and "
                "consider restricting unnecessary features."
            )
        }
    }

    # Only create header recommendations when headers were actually checked
    if headers:

        for header_name, recommendation in header_recommendations.items():

            if headers.get(header_name) is False:
                recommendations.append(recommendation)

    # TLS certificate recommendation
    days_remaining = ssl_result.get("days_until_expiry")

    if days_remaining is not None:

        if days_remaining < 0:

            recommendations.append({
                "title": "Review expired TLS certificate",
                "why": (
                    "The TLS certificate appears to have expired."
                ),
                "action": (
                    "Renew or replace the certificate through the "
                    "appropriate certificate-management process."
                )
            })

        elif days_remaining <= 30:

            recommendations.append({
                "title": "Review upcoming TLS certificate expiry",
                "why": (
                    "The TLS certificate is scheduled to expire "
                    "within 30 days."
                ),
                "action": (
                    "Plan certificate renewal before the expiry date "
                    "and verify certificate renewal monitoring."
                )
            })

    # Add limitations as informational recommendations
    limitations = risk.get("limitations", [])

    for limitation in limitations:

        recommendations.append({
            "title": "Review analysis limitation",
            "why": limitation,
            "action": (
                "Treat this item as unverified information rather "
                "than a confirmed security finding."
            )
        })

    # Always return something
    if not recommendations:

        recommendations.append({
            "title": "No specific recommendations",
            "why": (
                "The currently implemented checks did not produce "
                "a specific recommendation."
            ),
            "action": (
                "Continue routine security reviews, patching, "
                "access-control reviews, and application-specific testing."
            )
        })

    return recommendations