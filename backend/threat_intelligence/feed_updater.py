"""OpenPhish Community Feed Updater.

Downloads, validates, normalizes, and ingests public phishing feeds into the local SQLite database.
Supports fully offline operation using previously cached records.
Preserves the working database safely if a download or update fails.

Licensing Notice:
OpenPhish Community Feed data is provided subject to OpenPhish licensing terms
(free for research, evaluation, and non-commercial security use).
"""
import hashlib
import time
from datetime import datetime, timezone
from typing import Dict, Any, List
import httpx

from app.db import SessionLocal
from .database import ThreatRecord
from .normalization import normalize_threat_url, extract_domain

OPENPHISH_COMMUNITY_FEED_URL = "https://openphish.com/feed.txt"

# Feed update status tracking in-memory & persisted in metadata
FEED_STATUS = {
    "feed_name": "OpenPhish Community Feed",
    "feed_url": OPENPHISH_COMMUNITY_FEED_URL,
    "last_update_attempt": None,
    "last_successful_update": None,
    "total_records_ingested": 0,
    "last_error": None,
    "licensing": "OpenPhish Community Feed terms (non-commercial / research use)"
}


def compute_url_sha256(url: str) -> str:
    """Compute SHA-256 hash of canonicalized URL for record identification."""
    return hashlib.sha256(url.encode("utf-8")).hexdigest()


async def update_openphish_feed(feed_url: str = OPENPHISH_COMMUNITY_FEED_URL, timeout_secs: float = 15.0) -> Dict[str, Any]:
    """Download OpenPhish community feed and safely merge records into the local database."""
    now_str = datetime.now(timezone.utc).isoformat()
    FEED_STATUS["last_update_attempt"] = now_str
    FEED_STATUS["last_error"] = None

    print(f"[ThreatIntel] Fetching OpenPhish feed from {feed_url}...")
    try:
        async with httpx.AsyncClient(timeout=timeout_secs, follow_redirects=True) as client:
            resp = await client.get(feed_url)
            if resp.status_code != 200:
                err_msg = f"HTTP {resp.status_code}: Unable to download feed from {feed_url}"
                FEED_STATUS["last_error"] = err_msg
                return {
                    "success": False,
                    "error": err_msg,
                    "status": FEED_STATUS
                }
            text_data = resp.text
    except Exception as e:
        err_msg = f"Network/Connection error downloading feed: {e}"
        FEED_STATUS["last_error"] = err_msg
        print(f"[ThreatIntel] Feed update failed: {err_msg}. Preserving existing local database.")
        return {
            "success": False,
            "error": err_msg,
            "status": FEED_STATUS
        }

    lines = [line.strip() for line in text_data.splitlines() if line.strip() and not line.startswith("#")]
    if not lines:
        err_msg = "Downloaded feed was empty or contained only comments."
        FEED_STATUS["last_error"] = err_msg
        return {"success": False, "error": err_msg, "status": FEED_STATUS}

    added = 0
    updated = 0
    duplicates = 0
    now = datetime.now(timezone.utc)

    session = SessionLocal()
    try:
        # Load existing known URLs/hashes to deduplicate in memory
        existing_urls = set(
            u for (u,) in session.query(ThreatRecord.indicator_value)
            .filter(ThreatRecord.indicator_type == "url")
            .all()
        )

        records_to_add = []
        domains_to_add = set()

        for raw_u in lines:
            try:
                norm_u = normalize_threat_url(raw_u)
                if not norm_u:
                    continue
                
                url_hash = compute_url_sha256(norm_u)
                dom = extract_domain(norm_u)

                if norm_u in existing_urls:
                    duplicates += 1
                    continue

                existing_urls.add(norm_u)
                records_to_add.append(ThreatRecord(
                    indicator_type="url",
                    indicator_value=norm_u,
                    threat_level="MALICIOUS",
                    category="phishing",
                    malware_family="OpenPhish-Feed",
                    source="OpenPhish Community Feed",
                    first_seen=now,
                    last_updated=now,
                    details={"url_sha256": url_hash, "original_raw": raw_u}
                ))
                added += 1

                # Collect domain if valid
                if dom and len(dom) > 3 and "." in dom:
                    domains_to_add.add(dom)

            except Exception:
                continue

        # Also add parent domains if not already recorded
        existing_doms = set(
            d for (d,) in session.query(ThreatRecord.indicator_value)
            .filter(ThreatRecord.indicator_type == "domain")
            .all()
        )
        for dom in domains_to_add:
            if dom not in existing_doms:
                existing_doms.add(dom)
                records_to_add.append(ThreatRecord(
                    indicator_type="domain",
                    indicator_value=dom,
                    threat_level="SUSPICIOUS",
                    category="phishing-host",
                    malware_family="OpenPhish-Host",
                    source="OpenPhish Community Feed",
                    first_seen=now,
                    last_updated=now,
                    details={"extracted_from_feed": True}
                ))
                added += 1

        if records_to_add:
            session.bulk_save_objects(records_to_add)
            session.commit()

        FEED_STATUS["last_successful_update"] = now.isoformat()
        FEED_STATUS["total_records_ingested"] = len(existing_urls)
        print(f"[ThreatIntel] Feed update succeeded: {added} new indicators added, {duplicates} duplicates skipped.")

        return {
            "success": True,
            "feed_source": "OpenPhish Community Feed",
            "records_processed": len(lines),
            "records_added": added,
            "duplicates_skipped": duplicates,
            "status": FEED_STATUS
        }

    except Exception as e:
        session.rollback()
        err_msg = f"Database ingestion transaction error: {e}"
        FEED_STATUS["last_error"] = err_msg
        return {"success": False, "error": err_msg, "status": FEED_STATUS}
    finally:
        session.close()


def get_feed_status() -> Dict[str, Any]:
    """Retrieve status of the threat intelligence feed."""
    return dict(FEED_STATUS)
