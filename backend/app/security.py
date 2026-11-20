import ipaddress, socket
from urllib.parse import urlparse
def is_safe_host(url: str) -> bool:
    """SSRF guard: block private/loopback/link-local targets before any outbound fetch."""
    h = urlparse(url).hostname
    if not h: return False
    try:
        for i in socket.getaddrinfo(h, None):
            ip = ipaddress.ip_address(i[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved: return False
    except Exception: return False
    return True
