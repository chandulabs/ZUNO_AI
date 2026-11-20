"""Local Threat Intelligence Lookup Engine.

Provides high-speed indexed lookups for URLs, domains, and file hashes
against the local threat intelligence database without any external network calls.
"""
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from sqlalchemy import func, or_
from .database import get_session, ThreatRecord
from .normalization import normalize_threat_url, extract_domain, normalize_hash
from .schemas import ThreatLookupResult, ThreatDatabaseStats


def _iso(dt: Optional[datetime]) -> Optional[str]:
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat(timespec="seconds").replace("+00:00", "Z")


def check_database_status() -> Dict[str, Any]:
    """Check whether threat intelligence database is reachable and populated."""
    session = get_session()
    try:
        count = session.query(func.count(ThreatRecord.id)).scalar() or 0
        return {"available": True, "count": count, "empty": count == 0}
    except Exception as e:
        return {"available": False, "count": 0, "empty": True, "error": str(e)}
    finally:
        session.close()


def lookup_url(raw_url: str) -> ThreatLookupResult:
    """Look up a URL in the local threat intelligence database."""
    db_status = check_database_status()
    if not db_status["available"]:
        return ThreatLookupResult(
            status="DATABASE_UNAVAILABLE",
            message="Local threat intelligence database is unreachable."
        )
    if db_status["empty"]:
        return ThreatLookupResult(
            status="DATABASE_EMPTY",
            message="Local threat intelligence database is empty. No threat feeds imported."
        )

    norm_url = normalize_threat_url(raw_url)
    domain = extract_domain(raw_url)

    session = get_session()
    try:
        # 1. Exact URL match
        rec = session.query(ThreatRecord).filter(
            ThreatRecord.indicator_type == "url",
            ThreatRecord.indicator_value == raw_url.strip()
        ).first()

        if rec:
            return ThreatLookupResult(
                status=rec.threat_level,
                match_type="exact_url",
                matched_value=rec.indicator_value,
                threat_level=rec.threat_level,
                category=rec.category,
                malware_family=rec.malware_family,
                source=rec.source,
                first_seen=_iso(rec.first_seen),
                last_updated=_iso(rec.last_updated),
                details=rec.details,
                message=f"Exact URL flagged as {rec.threat_level} ({rec.category}) in {rec.source}.",
                is_domain_match=False
            )

        # 2. Normalized URL match
        if norm_url and norm_url != raw_url.strip():
            rec = session.query(ThreatRecord).filter(
                ThreatRecord.indicator_type == "url",
                ThreatRecord.indicator_value == norm_url
            ).first()
            if rec:
                return ThreatLookupResult(
                    status=rec.threat_level,
                    match_type="normalized_url",
                    matched_value=rec.indicator_value,
                    threat_level=rec.threat_level,
                    category=rec.category,
                    malware_family=rec.malware_family,
                    source=rec.source,
                    first_seen=_iso(rec.first_seen),
                    last_updated=_iso(rec.last_updated),
                    details=rec.details,
                    message=f"Normalized URL matches known {rec.threat_level} entry ({rec.category}) from {rec.source}.",
                    is_domain_match=False
                )

        # 3. Domain match
        if domain:
            rec = session.query(ThreatRecord).filter(
                ThreatRecord.indicator_type == "domain",
                ThreatRecord.indicator_value == domain
            ).first()
            if rec:
                return ThreatLookupResult(
                    status=rec.threat_level,
                    match_type="domain",
                    matched_value=rec.indicator_value,
                    threat_level=rec.threat_level,
                    category=rec.category,
                    malware_family=rec.malware_family,
                    source=rec.source,
                    first_seen=_iso(rec.first_seen),
                    last_updated=_iso(rec.last_updated),
                    details=rec.details,
                    message=f"Parent domain '{domain}' is listed as {rec.threat_level} ({rec.category}) in {rec.source}.",
                    is_domain_match=True
                )

        return ThreatLookupResult(
            status="NO_MATCH",
            message="No matching URL or domain in local threat intelligence database."
        )
    except Exception as e:
        return ThreatLookupResult(
            status="DATABASE_UNAVAILABLE",
            message=f"Error querying local threat intelligence: {e}"
        )
    finally:
        session.close()


def lookup_domain(raw_domain: str) -> ThreatLookupResult:
    """Look up a domain directly in the local threat intelligence database."""
    db_status = check_database_status()
    if not db_status["available"]:
        return ThreatLookupResult(status="DATABASE_UNAVAILABLE", message="Database unreachable.")
    if db_status["empty"]:
        return ThreatLookupResult(status="DATABASE_EMPTY", message="Threat intelligence database is empty.")

    dom = extract_domain(raw_domain)
    if not dom:
        return ThreatLookupResult(status="NO_MATCH", message="Invalid domain provided.")

    try:
        with get_session() as session:
            rec = session.query(ThreatRecord).filter(
                ThreatRecord.indicator_type == "domain",
                ThreatRecord.indicator_value == dom
            ).first()

            if rec:
                return ThreatLookupResult(
                    status=rec.threat_level,
                    match_type="domain",
                    matched_value=rec.indicator_value,
                    threat_level=rec.threat_level,
                    category=rec.category,
                    malware_family=rec.malware_family,
                    source=rec.source,
                    first_seen=_iso(rec.first_seen),
                    last_updated=_iso(rec.last_updated),
                    details=rec.details,
                    message=f"Domain '{dom}' matches local {rec.threat_level} record from {rec.source}.",
                    is_domain_match=True
                )
            return ThreatLookupResult(status="NO_MATCH", message="Domain not found in local threat database.")
    except Exception as e:
        return ThreatLookupResult(status="DATABASE_UNAVAILABLE", message=f"Query error: {e}")


def lookup_hash(file_hash: str) -> ThreatLookupResult:
    """Look up a SHA-256 or MD5 file hash in the local threat intelligence database."""
    db_status = check_database_status()
    if not db_status["available"]:
        return ThreatLookupResult(status="DATABASE_UNAVAILABLE", message="Database unreachable.")
    if db_status["empty"]:
        return ThreatLookupResult(status="DATABASE_EMPTY", message="Threat intelligence database is empty.")

    h = normalize_hash(file_hash)
    if not h:
        return ThreatLookupResult(status="NO_MATCH", message="Invalid hash string.")
    htype = "sha256" if len(h) == 64 else "md5"

    try:
        with get_session() as session:
            rec = session.query(ThreatRecord).filter(
                ThreatRecord.indicator_type == htype,
                ThreatRecord.indicator_value == h
            ).first()

            if rec:
                return ThreatLookupResult(
                    status=rec.threat_level,
                    match_type="file_hash",
                    matched_value=rec.indicator_value,
                    threat_level=rec.threat_level,
                    category=rec.category,
                    malware_family=rec.malware_family,
                    source=rec.source,
                    first_seen=_iso(rec.first_seen),
                    last_updated=_iso(rec.last_updated),
                    details=rec.details,
                    message=f"File {htype.upper()} matches known {rec.threat_level} malware ({rec.malware_family or rec.category}) in {rec.source}.",
                    is_domain_match=False
                )
            return ThreatLookupResult(status="NO_MATCH", message="File hash not found in local threat database.")
    except Exception as e:
        return ThreatLookupResult(status="DATABASE_UNAVAILABLE", message=f"Query error: {e}")


def get_threat_stats() -> ThreatDatabaseStats:
    """Get aggregated metrics and statistics of the local threat database."""
    try:
        with get_session() as session:
            total = session.query(func.count(ThreatRecord.id)).scalar() or 0
            if total == 0:
                return ThreatDatabaseStats(available=True, total_records=0)

            mal_urls = session.query(func.count(ThreatRecord.id)).filter(
                ThreatRecord.indicator_type == "url",
                ThreatRecord.threat_level == "MALICIOUS"
            ).scalar() or 0

            susp_urls = session.query(func.count(ThreatRecord.id)).filter(
                ThreatRecord.indicator_type == "url",
                ThreatRecord.threat_level == "SUSPICIOUS"
            ).scalar() or 0

            mal_doms = session.query(func.count(ThreatRecord.id)).filter(
                ThreatRecord.indicator_type == "domain",
                ThreatRecord.threat_level == "MALICIOUS"
            ).scalar() or 0

            susp_doms = session.query(func.count(ThreatRecord.id)).filter(
                ThreatRecord.indicator_type == "domain",
                ThreatRecord.threat_level == "SUSPICIOUS"
            ).scalar() or 0

            hashes = session.query(func.count(ThreatRecord.id)).filter(
                ThreatRecord.indicator_type.in_(["sha256", "md5"])
            ).scalar() or 0

            cat_rows = session.query(ThreatRecord.category, func.count(ThreatRecord.id)).group_by(ThreatRecord.category).all()
            src_rows = session.query(ThreatRecord.source, func.count(ThreatRecord.id)).group_by(ThreatRecord.source).all()
            last_dt = session.query(func.max(ThreatRecord.last_updated)).scalar()

            return ThreatDatabaseStats(
                available=True,
                total_records=total,
                malicious_urls=mal_urls,
                suspicious_urls=susp_urls,
                malicious_domains=mal_doms,
                suspicious_domains=susp_doms,
                file_hashes=hashes,
                categories=dict(cat_rows),
                sources=dict(src_rows),
                last_import=_iso(last_dt)
            )
    except Exception:
        return ThreatDatabaseStats(available=False, total_records=0)


def search_threat_records(query: str, limit: int = 50) -> List[Dict[str, Any]]:
    """Search threat intelligence records by keyword/value."""
    q = query.strip()
    if not q:
        return []
    try:
        with get_session() as session:
            rows = session.query(ThreatRecord).filter(
                or_(
                    ThreatRecord.indicator_value.ilike(f"%{q}%"),
                    ThreatRecord.malware_family.ilike(f"%{q}%"),
                    ThreatRecord.source.ilike(f"%{q}%"),
                    ThreatRecord.category.ilike(f"%{q}%")
                )
            ).order_by(ThreatRecord.last_updated.desc()).limit(limit).all()

            return [
                {
                    "id": r.id,
                    "indicator_type": r.indicator_type,
                    "indicator_value": r.indicator_value,
                    "threat_level": r.threat_level,
                    "category": r.category,
                    "malware_family": r.malware_family,
                    "source": r.source,
                    "first_seen": _iso(r.first_seen),
                    "last_updated": _iso(r.last_updated),
                    "details": r.details,
                }
                for r in rows
            ]
    except Exception:
        return []
