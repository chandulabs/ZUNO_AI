"""Pydantic schemas for Local Threat Intelligence Engine."""
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ThreatRecordCreate(BaseModel):
    indicator_type: str = Field(..., description="url | domain | sha256 | md5")
    indicator_value: str = Field(..., description="Exact or normalized indicator value")
    threat_level: str = Field("MALICIOUS", description="MALICIOUS | SUSPICIOUS")
    category: str = Field("phishing", description="phishing | malware | c2 | scam")
    malware_family: Optional[str] = None
    source: str = Field("Manual Import", description="Provenance source, e.g. PhishTank, OpenPhish")
    details: Optional[Dict[str, Any]] = None


class ThreatLookupResult(BaseModel):
    status: str = Field(..., description="MALICIOUS | SUSPICIOUS | NO_MATCH | DATABASE_EMPTY | DATABASE_UNAVAILABLE")
    match_type: Optional[str] = Field(None, description="exact_url | normalized_url | domain | file_hash")
    matched_value: Optional[str] = None
    threat_level: Optional[str] = None
    category: Optional[str] = None
    malware_family: Optional[str] = None
    source: Optional[str] = None
    first_seen: Optional[str] = None
    last_updated: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    message: str = ""
    is_domain_match: bool = False


class ThreatDatabaseStats(BaseModel):
    available: bool = True
    total_records: int = 0
    malicious_urls: int = 0
    suspicious_urls: int = 0
    malicious_domains: int = 0
    suspicious_domains: int = 0
    file_hashes: int = 0
    categories: Dict[str, int] = Field(default_factory=dict)
    sources: Dict[str, int] = Field(default_factory=dict)
    last_import: Optional[str] = None


class ImportResult(BaseModel):
    success: bool
    total_processed: int
    added: int
    updated: int
    duplicates_skipped: int
    invalid_rows: int
    source: str
    message: str
