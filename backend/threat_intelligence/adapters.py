"""Local Threat Intelligence Adapters.

Replaces legacy external VirusTotal and URLhaus API calls with 100% server-local
threat intelligence lookups against the local indexed database.

Strictly zero external network calls.
"""
from typing import Dict, Any, List
from .lookup import (
    lookup_url as local_lookup_url,
    lookup_domain as local_lookup_domain,
    lookup_hash as local_lookup_hash,
    get_threat_stats,
    check_database_status
)
from .importer import seed_initial_threat_intelligence


async def lookup_url(url: str) -> List[Dict[str, Any]]:
    """Local threat intelligence query for a URL.
    
    Returns structured results representing local threat feeds.
    """
    res = local_lookup_url(url)
    return [{
        "source": "Local Threat Intelligence",
        "status": res.status,
        "match_type": res.match_type,
        "matched_value": res.matched_value,
        "category": res.category,
        "malware_family": res.malware_family,
        "feed_source": res.source,
        "first_seen": res.first_seen,
        "last_updated": res.last_updated,
        "message": res.message,
        "is_domain_match": res.is_domain_match,
        "configured": True
    }]


async def lookup_apk_hash(sha256_hash: str) -> Dict[str, Any]:
    """Local threat intelligence query for an APK file hash."""
    res = local_lookup_hash(sha256_hash)
    return {
        "source": "Local Threat Intelligence",
        "status": res.status,
        "match_type": res.match_type,
        "matched_value": res.matched_value,
        "category": res.category,
        "malware_family": res.malware_family,
        "feed_source": res.source,
        "first_seen": res.first_seen,
        "last_updated": res.last_updated,
        "message": res.message,
        "is_domain_match": False,
        "configured": True
    }


def summarize(ti_list: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Summarize local threat intelligence findings for a scanned target."""
    if not ti_list:
        return {
            "status": "NO_MATCH",
            "message": "No local threat intelligence matches.",
            "corroborated": False,
            "malicious_providers": [],
            "providers_usable": 0
        }

    first = ti_list[0]
    st = first.get("status", "NO_MATCH")
    is_mal = st == "MALICIOUS"
    is_susp = st == "SUSPICIOUS"

    return {
        "status": st,
        "message": first.get("message", ""),
        "match_type": first.get("match_type"),
        "is_domain_match": first.get("is_domain_match", False),
        "category": first.get("category"),
        "malware_family": first.get("malware_family"),
        "feed_source": first.get("feed_source"),
        "corroborated": is_mal,
        "malicious_providers": [first.get("feed_source")] if is_mal and first.get("feed_source") else [],
        "providers_usable": 1 if st in ("MALICIOUS", "SUSPICIOUS", "NO_MATCH") else 0
    }


def configured() -> Dict[str, bool]:
    """Status of local threat intelligence database."""
    st = check_database_status()
    return {"Local Threat Intelligence": st["available"] and not st["empty"]}
