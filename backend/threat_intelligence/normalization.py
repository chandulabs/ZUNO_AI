"""URL, Domain, and Hash Normalization Utilities.

Strictly local normalization for consistent database lookups and deduplication.
Submitted targets are never visited or queried externally.
"""
import re
from urllib.parse import urlparse


def normalize_hash(val: str) -> str:
    """Normalize and validate MD5 or SHA-256 hash."""
    if not val:
        return ""
    val = val.strip().lower()
    if re.fullmatch(r"[a-f0-9]{32}", val) or re.fullmatch(r"[a-f0-9]{64}", val):
        return val
    return ""


def extract_domain(url_or_domain: str) -> str:
    """Extract and normalize host/domain from a URL or raw domain string."""
    s = url_or_domain.strip().lower()
    if not s:
        return ""
    if "://" not in s:
        s = "http://" + s
    try:
        p = urlparse(s)
        h = p.hostname or ""
        return h.strip().lower().rstrip(".")
    except Exception:
        return ""


def normalize_threat_url(url: str) -> str:
    """Normalize URL for threat database indexing and matching.
    
    Removes trailing slashes, default ports, lowercases protocol and hostname,
    preserves query and path semantics.
    """
    s = url.strip()
    if not s:
        return ""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", s):
        s = "http://" + s
    try:
        p = urlparse(s)
        scheme = (p.scheme or "http").lower()
        host = (p.hostname or "").lower().rstrip(".")
        port = p.port
        port_str = ""
        if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
            port_str = f":{port}"
        
        path = p.path or "/"
        if len(path) > 1 and path.endswith("/"):
            path = path.rstrip("/")
            
        query = f"?{p.query}" if p.query else ""
        return f"{scheme}://{host}{port_str}{path}{query}"
    except Exception:
        return url.strip().lower()
