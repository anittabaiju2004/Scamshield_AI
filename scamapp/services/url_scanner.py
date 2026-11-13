
import re
import ipaddress
from urllib.parse import urlparse, unquote


SUSPICIOUS_KEYWORDS = [
    "login-verify",
    "account-verify",
    "secure-update",
    "password-reset",
    "free-prize",
    "claim-reward",
    "banking-login",
    "verify-account",
    "wallet-connect",
    "payment-confirm",
]

URL_SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "shorturl.at",
    "is.gd",
    "cutt.ly",
    "rb.gy",
    "ow.ly",
]


def scan_url(url):
    """
    Analyze a URL using rule-based detection.
    Returns a risk score, classification and reasons.
    """

    url = url.strip()

    if not url:
        raise ValueError("Please enter a URL.")

    if len(url) > 2048:
        raise ValueError("URL is too long.")

    # Add scheme if the user enters only a domain
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "https://" + url

    parsed = urlparse(url)

    if parsed.scheme.lower() not in ["http", "https"]:
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    if not parsed.hostname:
        raise ValueError("Please enter a valid URL.")

    hostname = parsed.hostname.lower().rstrip(".")
    full_url = unquote(url).lower()

    risk_score = 0
    reasons = []

    def add_risk(points, reason):
        nonlocal risk_score
        risk_score += points
        reasons.append({
            "points": points,
            "reason": reason
        })

    # 1. HTTP instead of HTTPS
    if parsed.scheme.lower() == "http":
        add_risk(5, "Website uses HTTP instead of HTTPS.")

    # 2. IP address instead of domain name
    try:
        ipaddress.ip_address(hostname)
        add_risk(25, "Website uses an IP address instead of a domain.")
    except ValueError:
        pass

    # 3. @ symbol in URL
    if "@" in parsed.netloc:
        add_risk(20, "URL contains an @ symbol, which can hide the actual destination.")

    # 4. Suspicious keywords
    found_keywords = [
        keyword for keyword in SUSPICIOUS_KEYWORDS
        if keyword in full_url
    ]

    if found_keywords:
        add_risk(
            15,
            "Suspicious keywords detected: " + ", ".join(found_keywords)
        )

    # 5. URL shortener
    if hostname in URL_SHORTENERS:
        add_risk(15, "URL uses a known URL shortening service.")

    # 6. Excessive subdomains
    if len(hostname.split(".")) > 4:
        add_risk(10, "URL contains an unusually large number of subdomains.")

    # 7. Suspicious characters
    if "%" in url:
        add_risk(10, "URL contains encoded characters.")

    # 8. Multiple hyphens in hostname
    if hostname.count("-") >= 3:
        add_risk(10, "Domain contains multiple hyphens.")

    # Keep score within 100
    risk_score = min(risk_score, 100)

    # Classification
    if risk_score >= 50:
        result = "High Risk"
    elif risk_score >= 20:
        result = "Suspicious"
    else:
        result = "Low Risk"

    return {
        "url": url,
        "domain": hostname,
        "risk_score": risk_score,
        "result": result,
        "reasons": reasons,
        "total_checks": 8,
    }
