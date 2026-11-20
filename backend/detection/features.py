"""URL validation, lexical feature extraction and rule-based analysis.

Extracts structured features for Random Forest, XGBoost, SHAP explainability, and rule heuristics.
Nothing in this module (or anywhere in PhishGuard) ever fetches or visits the submitted URL.
"""
import math
import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "bank", "confirm",
    "password", "wallet", "signin", "paypal", "apple", "free", "bonus",
    "credential", "security", "support", "billing", "auth", "recover",
    "validate", "unlock", "alert", "portal", "token", "payment", "authenticate"
]

BAD_TLDS = {
    "zip", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "country",
    "work", "support", "buzz", "racing", "surf", "rest", "cam", "loan", "fit", "live"
}

REDIRECT_PARAMS = [
    "url=", "redirect=", "dest=", "destination=", "return=", "next=", "target=", "r="
]

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly",
    "tiny.cc", "cutt.ly", "rb.gy", "rebrand.ly", "shorturl.at", "bl.ink"
}

SPECIAL_CHARS_PATTERN = re.compile(r"[_=?!%&@~*+$;^]")

# Order matters: the trained models (Random Forest, XGBoost) and SHAP expect exactly this feature order.
NAMES = [
    "url_len",
    "domain_len",
    "dots",
    "hyphens",
    "subdomains",
    "has_ip",
    "https",
    "keywords",
    "entropy",
    "bad_tld",
    "special_chars",
    "digit_ratio",
    "at_sym",
    "is_shortened",
    "punycode",
    "homograph_indicator",
    "suspicious_hostname",
    "path_len",
    "query_len",
    "url_encoding",
    "redirect_params",
    "path_depth"
]

# Human-readable metadata for each feature (used by the SHAP / explainability UI and PDF reports).
FEATURE_INFO = {
    "url_len":              {"label": "URL length",                   "desc": "Very long URLs are frequently used to hide deceptive destinations or tracking payloads."},
    "domain_len":           {"label": "Domain length",                "desc": "Abnormally long hostnames often conceal brand impersonations or generated names."},
    "dots":                 {"label": "Number of dots",               "desc": "Many dots typically indicate nested subdomains or obfuscated path structures."},
    "hyphens":              {"label": "Number of hyphens",            "desc": "Hyphens are commonly used to craft deceptive brand names (e.g. secure-login-bank)."},
    "subdomains":           {"label": "Subdomain count",              "desc": "Deep subdomain nesting is used to mislead users into seeing a legitimate brand name."},
    "has_ip":               {"label": "IP address host",             "desc": "Legitimate web services use domain names; direct IP hosts are high-risk indicators."},
    "https":                {"label": "HTTPS usage",                  "desc": "Plain HTTP lacks encryption (though modern phishing frequently adopts free TLS)."},
    "keywords":             {"label": "Suspicious keywords",          "desc": "Words like 'login', 'verify', 'account', and 'secure' serve as psychological lures."},
    "entropy":              {"label": "Character entropy",            "desc": "High Shannon entropy indicates random strings, hex tokens, or obfuscation."},
    "bad_tld":              {"label": "High-abuse TLD",               "desc": "TLDs known for high rates of registration abuse (.xyz, .top, .tk, .click)."},
    "special_chars":        {"label": "Special character count",      "desc": "Frequency of characters like _, =, ?, &, %, and @ used in obfuscation or tracking."},
    "digit_ratio":          {"label": "Digit ratio",                  "desc": "Proportion of numeric digits across the entire URL length."},
    "at_sym":               {"label": "'@' symbol detection",         "desc": "The '@' character can disguise the true host by placing a deceptive prefix."},
    "is_shortened":         {"label": "URL shortening service",       "desc": "Shorteners (bit.ly, tinyurl) mask the actual destination host."},
    "punycode":             {"label": "Punycode indicator",           "desc": "Internationalized domain names ('xn--') used in homograph attacks to mimic letters."},
    "homograph_indicator":  {"label": "Homograph indicator",          "desc": "Hostname contains Punycode or character mixtures typical of domain spoofing."},
    "suspicious_hostname":  {"label": "Suspicious hostname pattern",  "desc": "Patterns such as consecutive hyphens, hex tokens, or multi-brand labels in host."},
    "path_len":             {"label": "Path length",                  "desc": "Extended path segments frequently mask redirection scripts or credential harvesters."},
    "query_len":            {"label": "Query string length",          "desc": "Large query strings often contain victim tokens, encoded parameters, or redirects."},
    "url_encoding":         {"label": "URL percent-encoding",         "desc": "Frequent percent-encoding (%xx) can be used to bypass simplistic string matching filters."},
    "redirect_params":      {"label": "Redirect parameter",           "desc": "Parameters like 'url=' or 'redirect=' commonly signal open redirect exploitation."},
    "path_depth":           {"label": "Path subdirectory depth",      "desc": "Deep hierarchical directory paths common in staged credential harvesters."}
}

MAX_URL_LEN = 2048
_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$", re.I)


def normalize(u: str) -> str:
    """Validate and normalise user input into an http(s) URL. Raises ValueError with a user-readable message."""
    if not isinstance(u, str) or not u.strip():
        raise ValueError("Please enter a URL.")
    u = u.strip()
    if len(u) > MAX_URL_LEN:
        raise ValueError(f"URL is too long (max {MAX_URL_LEN} characters).")
    if re.search(r"[\s\x00-\x1f\x7f]", u):
        raise ValueError("URL must not contain spaces or control characters.")
    sm = re.match(r"^([a-z][a-z0-9+.\-]*)://", u, re.I)
    if sm and sm.group(1).lower() not in ("http", "https"):
        raise ValueError(f"Unsupported URL scheme '{sm.group(1)}'. Only http and https are accepted.")
    if not sm:
        bare = re.match(r"^(javascript|data|mailto|file|tel|vbscript|blob|about):", u, re.I)
        if bare:
            raise ValueError(f"Unsupported URL scheme '{bare.group(1)}'. Only http and https are accepted.")
        u = "http://" + u
    try:
        p = urlparse(u)
        _ = p.port
    except ValueError:
        raise ValueError("Invalid URL (bad port or host).")
    h = p.hostname
    if not h:
        raise ValueError("Invalid URL: no host found.")
    is_ipv4 = re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", h) is not None
    if not is_ipv4 and ":" not in h:
        labels = h.rstrip(".").split(".")
        if len(labels) < 2 or not all(_LABEL.match(l) for l in labels):
            raise ValueError("Invalid URL: host is not a valid domain name.")
    return u


def entropy(s: str) -> float:
    """Shannon entropy of a string."""
    if not s:
        return 0.0
    return -sum(c / len(s) * math.log2(c / len(s)) for c in map(s.count, set(s)))


def extract(url: str) -> dict:
    """Extract lexical and structural features from a validated URL."""
    p = urlparse(url)
    h = (p.hostname or "").lower()
    path = p.path or ""
    query = p.query or ""
    parts = h.split(".")
    u_lower = url.lower()

    # Digits and ratios
    digits = sum(c.isdigit() for c in url)
    u_len = len(url)
    digit_ratio = round(digits / u_len, 4) if u_len > 0 else 0.0

    # Path depth
    path_depth = len([seg for seg in path.split("/") if seg])

    # Punycode / IDN
    has_punycode = int("xn--" in h)

    # URL encoding (%xx)
    url_encoding_count = len(re.findall(r"%[0-9a-fA-F]{2}", url))

    # Redirect indicators
    has_redirect = int(any(param in u_lower for param in REDIRECT_PARAMS))

    # IPv4 host check
    is_ip = int(bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", h)))

    # Bad TLD check
    tld = parts[-1].lower() if parts else ""
    is_bad_tld = int(tld in BAD_TLDS)

    # Subdomains count (e.g. sub.domain.com -> 1, a.b.domain.com -> 2)
    subdomains = max(len(parts) - 2, 0) if not is_ip else 0

    # Special characters count
    special_chars_count = len(SPECIAL_CHARS_PATTERN.findall(url))

    # URL Shortener detection
    is_shortened = int(h in SHORTENER_DOMAINS or any(h.endswith("." + s) for s in SHORTENER_DOMAINS))

    # Homograph indicator: punycode or lookalike sequences
    homograph_indicator = int(has_punycode or bool(re.search(r"-[a-z0-9]{2,}-", h)))

    # Suspicious hostname pattern: consecutive hyphens, mixed digit-hex tokens, excessive subdomains
    suspicious_hostname = int(
        "--" in h or
        bool(re.search(r"[0-9a-f]{8,}", h)) or
        (subdomains >= 3 and not is_ip)
    )

    return {
        "url_len": u_len,
        "domain_len": len(h),
        "dots": url.count("."),
        "hyphens": url.count("-"),
        "subdomains": subdomains,
        "has_ip": is_ip,
        "https": int(p.scheme.lower() == "https"),
        "keywords": sum(k in u_lower for k in SUSPICIOUS_KEYWORDS),
        "entropy": round(entropy(url), 3),
        "bad_tld": is_bad_tld,
        "special_chars": special_chars_count,
        "digit_ratio": digit_ratio,
        "at_sym": int("@" in url),
        "is_shortened": is_shortened,
        "punycode": has_punycode,
        "homograph_indicator": homograph_indicator,
        "suspicious_hostname": suspicious_hostname,
        "path_len": len(path),
        "query_len": len(query),
        "url_encoding": url_encoding_count,
        "redirect_params": has_redirect,
        "path_depth": path_depth
    }


def describe(name: str, value) -> str:
    """One-sentence, human-readable description of a feature value."""
    v = value
    return {
        "url_len": f"The URL is {v} characters long.",
        "domain_len": f"The domain length is {v} characters.",
        "dots": f"The URL contains {v} dot(s).",
        "hyphens": f"The URL contains {v} hyphen(s).",
        "subdomains": f"The host has {v} subdomain level(s).",
        "has_ip": "The host is a raw IP address." if v else "The host is a domain name, not a raw IP address.",
        "https": "The URL uses HTTPS." if v else "The URL uses plain HTTP (no TLS).",
        "keywords": f"{v} suspicious keyword(s) appear in the URL.",
        "entropy": f"Character entropy is {v} bits.",
        "bad_tld": "The top-level domain is on the high-abuse list." if v else "The top-level domain is not on the high-abuse list.",
        "special_chars": f"The URL contains {v} special character(s) (_, =, ?, &, %, @, etc.).",
        "digit_ratio": f"{round(float(v) * 100, 1)}% of characters are digits.",
        "at_sym": "The URL contains an '@' symbol." if v else "The URL has no '@' symbol.",
        "is_shortened": "Uses a known URL shortening service (bit.ly, tinyurl, etc.)." if v else "Not using a known URL shortening service.",
        "punycode": "The domain uses Punycode (IDN homograph indicator)." if v else "No Punycode encoding in host.",
        "homograph_indicator": "Contains homograph or spoofing indicators." if v else "No homograph indicators detected.",
        "suspicious_hostname": "Host contains suspicious patterns (consecutive hyphens or hex tokens)." if v else "Standard hostname pattern.",
        "path_len": f"The URL path is {v} characters long.",
        "query_len": f"The query string is {v} characters long.",
        "url_encoding": f"The URL contains {v} percent-encoded token(s).",
        "redirect_params": "Contains suspicious redirect parameter(s)." if v else "No redirect parameters found.",
        "path_depth": f"Path has {v} directory level(s)."
    }.get(name, f"{name} = {v}")


def feature_table(f: dict) -> list:
    """Return an ordered list of feature dicts for tabular display in the UI and reports."""
    return [
        {
            "name": n,
            "label": FEATURE_INFO[n]["label"],
            "value": f.get(n, 0),
            "description": describe(n, f.get(n, 0))
        }
        for n in NAMES
    ]


def rule_analysis(f: dict) -> dict:
    """Deterministic, transparent rule-based analysis."""
    triggered = []
    score = 0

    if f.get("has_ip"):
        triggered.append({"id": "ip_host", "label": "Host is an IP address", "weight": 25, "desc": "Direct IP hosting bypasses reputation systems."})
        score += 25
    if f.get("at_sym"):
        triggered.append({"id": "at_symbol", "label": "'@' symbol in URL", "weight": 20, "desc": "Obfuscates real destination."})
        score += 20
    if f.get("is_shortened"):
        triggered.append({"id": "shortened_url", "label": "Known URL shortener used", "weight": 18, "desc": "Hides actual target destination."})
        score += 18
    if f.get("bad_tld"):
        triggered.append({"id": "high_abuse_tld", "label": "High-abuse top-level domain", "weight": 18, "desc": "Associated with disposable phishing domains."})
        score += 18
    if f.get("punycode") or f.get("homograph_indicator"):
        triggered.append({"id": "homograph_spoofing", "label": "Punycode or homograph pattern", "weight": 22, "desc": "Possible homograph domain spoofing."})
        score += 22
    if f.get("suspicious_hostname"):
        triggered.append({"id": "suspicious_host", "label": "Deceptive hostname pattern", "weight": 16, "desc": "Consecutive hyphens or hex-encoded labels in host."})
        score += 16
    if f.get("redirect_params"):
        triggered.append({"id": "open_redirect", "label": "Suspicious redirect parameter", "weight": 15, "desc": "May redirect victim to an unverified third party."})
        score += 15
    if f.get("keywords", 0) >= 2:
        triggered.append({"id": "multiple_keywords", "label": f"{f['keywords']} suspicious lure keywords", "weight": 16, "desc": "High concentration of credential/banking terms."})
        score += 16
    elif f.get("keywords", 0) == 1:
        triggered.append({"id": "single_keyword", "label": "Suspicious lure keyword present", "weight": 8, "desc": "Includes security or credential lures."})
        score += 8
    if f.get("subdomains", 0) >= 3:
        triggered.append({"id": "deep_subdomains", "label": f"{f['subdomains']} subdomain levels", "weight": 14, "desc": "Used to conceal the actual root domain."})
        score += 14
    if f.get("url_len", 0) > 100:
        triggered.append({"id": "excessive_length", "label": "Excessive URL length (>100)", "weight": 10, "desc": "Hides parameters or payload."})
        score += 10
    if f.get("entropy", 0.0) > 4.5:
        triggered.append({"id": "high_entropy", "label": "High character entropy (>4.5 bits)", "weight": 12, "desc": "Suggests randomized tokens or obfuscation."})
        score += 12
    if f.get("special_chars", 0) >= 5:
        triggered.append({"id": "high_special_chars", "label": f"{f['special_chars']} special characters", "weight": 10, "desc": "High concentration of delimiter and encoding characters."})
        score += 10
    if not f.get("https"):
        triggered.append({"id": "no_https", "label": "Plain HTTP (no encryption)", "weight": 6, "desc": "Unencrypted connection."})
        score += 6

    score = min(100, score)
    return {
        "score": score,
        "triggered": triggered,
        "count": len(triggered),
        "level": "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW"
    }


def indicators(f: dict) -> list:
    """Flat list of triggered rule descriptions for reports."""
    return [t["label"] for t in rule_analysis(f)["triggered"]]
