"""Android APK Static Analysis Engine.

Performs static unpacking and inspection of Android packages using Androguard.
Zero dynamic execution; submitted APKs are never run.
Extracts package metadata, permissions, dangerous API calls, embedded URLs,
IP addresses, and performs local threat intelligence lookups on hashes and domains.
"""
import re
import hashlib
from typing import Dict, Any, List
from threat_intelligence import lookup as local_ti

# Android dangerous permissions weighting and security implications
RISKY_INFO = {
    "SEND_SMS": (12, "Can send SMS messages (premium-SMS fraud, unauthorized communication)."),
    "READ_SMS": (12, "Can read SMS messages (OTP / 2FA interception, credential theft)."),
    "RECEIVE_SMS": (10, "Can intercept incoming SMS messages (bypassing banking 2FA)."),
    "BIND_ACCESSIBILITY_SERVICE": (18, "Accessibility services can read screen contents and simulate taps (hallmark of modern banking trojans)."),
    "SYSTEM_ALERT_WINDOW": (12, "Can display deceptive overlays on top of legitimate banking/login apps."),
    "REQUEST_INSTALL_PACKAGES": (10, "Can silently prompt to install second-stage malicious payloads (dropper behavior)."),
    "READ_CONTACTS": (6, "Can harvest address book contacts for spam or social engineering."),
    "RECORD_AUDIO": (8, "Can record audio without explicit ongoing notification."),
    "CAMERA": (8, "Can capture photos/video from device cameras."),
    "ACCESS_FINE_LOCATION": (6, "Can track device physical GPS coordinates."),
    "BIND_DEVICE_ADMIN": (16, "Device-admin rights prevent uninstallation and allow remote lock/wipe."),
    "READ_CALL_LOG": (6, "Can exfiltrate call history."),
    "READ_PHONE_STATE": (4, "Can read unique hardware identifiers (IMEI, IMSI)."),
    "RECEIVE_BOOT_COMPLETED": (4, "Starts persistence automatically upon device boot."),
    "MANAGE_EXTERNAL_STORAGE": (6, "Broad read/write access across all shared storage files."),
    "WRITE_SETTINGS": (6, "Can modify system configuration."),
    "USE_BIOMETRIC": (4, "Requests biometric authentication access.")
}

RISKY = list(RISKY_INFO)
_IP_REGEX = re.compile(r"//(\d{1,3}(?:\.\d{1,3}){3})")


def risk_level(score: int) -> str:
    return "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW"


def file_hashes(path: str) -> dict:
    """Compute SHA-256, SHA-1, MD5, and file size in bytes."""
    h256 = hashlib.sha256()
    h1 = hashlib.sha1()
    md5 = hashlib.md5()
    size = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h256.update(chunk)
            h1.update(chunk)
            md5.update(chunk)
            size += len(chunk)
    return {
        "sha256": h256.hexdigest(),
        "sha1": h1.hexdigest(),
        "md5": md5.hexdigest(),
        "size_bytes": size
    }


def analyze(path: str) -> dict:
    """Perform static analysis on an APK file using Androguard."""
    from androguard.misc import AnalyzeAPK
    a, d, _ = AnalyzeAPK(path)

    perms = sorted(set(a.get_permissions()))
    urls, ips = set(), set()
    for dx in d:
        for s in dx.get_strings():
            found_urls = re.findall(r"https?://[^\s\"'<>]{4,200}", str(s))
            urls.update(found_urls)
    for u in urls:
        ips.update(_IP_REGEX.findall(u))

    risky = [p for p in perms if p.split(".")[-1] in RISKY_INFO]

    certs = []
    try:
        certs = [
            {
                "subject": c.subject.human_friendly,
                "issuer": c.issuer.human_friendly,
                "sha256": c.sha256.hex()
            }
            for c in a.get_certificates()
        ]
    except Exception:
        pass

    def safe(fn, default=None):
        try:
            return fn()
        except Exception:
            return default

    # Extract domains
    domains = sorted({re.sub(r"^https?://([^/:?#]+).*", r"\1", u) for u in urls})

    return {
        "package": a.get_package(),
        "app_name": a.get_app_name(),
        "version": a.get_androidversion_name(),
        "version_code": safe(a.get_androidversion_code),
        "min_sdk": safe(a.get_min_sdk_version),
        "target_sdk": safe(a.get_target_sdk_version),
        "main_activity": safe(a.get_main_activity),
        "activities": len(safe(a.get_activities, []) or []),
        "services": len(safe(a.get_services, []) or []),
        "receivers": len(safe(a.get_receivers, []) or []),
        "providers": len(safe(a.get_providers, []) or []),
        "permissions": perms,
        "risky_permissions": risky,
        "risky_permission_details": [
            {
                "permission": p,
                "name": p.split(".")[-1],
                "explanation": RISKY_INFO[p.split(".")[-1]][1],
                "weight": RISKY_INFO[p.split(".")[-1]][0]
            }
            for p in risky
        ],
        "urls": sorted(urls)[:200],
        "ips": sorted(ips),
        "domains": domains,
        "certificates": certs,
        "signed": bool(certs)
    }


def score(r: dict) -> dict:
    """Calculate static risk score from extracted indicators."""
    ind, pts = [], 0
    for p in r.get("risky_permissions", []):
        short = p.split(".")[-1]
        if short in RISKY_INFO:
            w, why = RISKY_INFO[short]
            pts += w
            ind.append({
                "indicator": f"High-risk permission: {short}",
                "weight": w,
                "detail": why
            })

    if r.get("ips"):
        pts += 10
        ind.append({
            "indicator": f"{len(r['ips'])} embedded hardcoded IP address(es)",
            "weight": 10,
            "detail": "Direct IP addresses indicate potential C2 servers or dynamic stage downloading."
        })

    if not r.get("signed"):
        pts += 8
        ind.append({
            "indicator": "Unsigned or invalid package certificate",
            "weight": 8,
            "detail": "Missing or corrupt developer signature block."
        })

    pts = min(100, pts)
    return {
        "score": pts,
        "level": risk_level(pts),
        "indicators": ind
    }


def check_apk_local_threat_intel(hashes: dict, domains: List[str]) -> List[dict]:
    """Check APK hash and extracted domains against local threat intelligence database."""
    ti_results = []

    # 1. Check SHA-256
    hash_match = local_ti.lookup_hash(hashes.get("sha256", ""))
    ti_results.append({
        "source": "Local Threat DB (File Hash)",
        "status": hash_match.status,
        "match_type": hash_match.match_type,
        "matched_value": hash_match.matched_value,
        "category": hash_match.category,
        "malware_family": hash_match.malware_family,
        "feed_source": hash_match.source,
        "message": hash_match.message,
        "is_domain_match": False
    })

    # 2. Check embedded domains
    for dom in domains[:30]:
        dom_match = local_ti.lookup_domain(dom)
        if dom_match.status in ("MALICIOUS", "SUSPICIOUS"):
            ti_results.append({
                "source": f"Local Threat DB (Domain: {dom})",
                "status": dom_match.status,
                "match_type": "domain",
                "matched_value": dom,
                "category": dom_match.category,
                "malware_family": dom_match.malware_family,
                "feed_source": dom_match.source,
                "message": dom_match.message,
                "is_domain_match": True
            })

    return ti_results
