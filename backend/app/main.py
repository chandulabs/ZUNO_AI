"""PhishGuard AI — Complete API-Free AI Cybersecurity Platform.

Production FastAPI Backend Server:
  - Random Forest & XGBoost local inference and comparison
  - SHAP TreeExplainer explainability for Random Forest
  - Local SQLite threat intelligence database with OpenPhish Community Feed updater
  - Androguard-based static APK malware analysis
  - Zero external API keys (no VirusTotal, no URLhaus, no cloud inference)
"""
import asyncio
import os
import re
import tempfile
import time
import uuid
import zipfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Any

try:
    from dotenv import load_dotenv
    for _p in (Path(__file__).resolve().parents[2] / ".env", Path(__file__).resolve().parents[1] / ".env"):
        if _p.exists():
            load_dotenv(_p, override=False)
except ImportError:
    pass

from fastapi import FastAPI, UploadFile, File, HTTPException, Query, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import Column, String, Integer, JSON, DateTime, Boolean, func, or_

from app.db import engine, SessionLocal, Base
from detection import features as F, predict as P, risk as R
from detection.ensemble import combine_predictions
from detection.orchestrator import scan_url_pipeline
from threat_intelligence import (
    adapters as TI,
    lookup as TI_Lookup,
    importer as TI_Importer,
    feed_updater as TI_Feed
)
from apk_analysis import analyze as APK
from reports.pdf import build_pdf
from training.model_registry import list_registered_models, load_manifest
from training.train import train_and_compare_models

try:
    from deep_learning.predict import predict_cnn, predict_bilstm, explain_dl
except ImportError:
    predict_cnn = lambda u: {"available": False, "probability": None, "message": "DL module unavailable"}
    predict_bilstm = lambda u: {"available": False, "probability": None, "message": "DL module unavailable"}
    explain_dl = lambda u: {"cnn": {"available": False}, "bilstm": {"available": False}}

Session = SessionLocal


class Scan(Base):
    __tablename__ = "scans"
    id = Column(String(64), primary_key=True)
    kind = Column(String(32))  # url | apk
    target = Column(String(2048))
    verdict = Column(String(32))
    result = Column(JSON)
    created = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class ScanJob(Base):
    """Database-backed scan progress for multi-worker production server environments."""
    __tablename__ = "scan_jobs"
    id = Column(String(64), primary_key=True)
    mode = Column(String(32))
    stages = Column(JSON)
    done = Column(Boolean, default=False)
    error = Column(String, nullable=True)
    verdict = Column(String(32), nullable=True)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))


Base.metadata.create_all(engine)

app = FastAPI(
    title="PhishGuard AI Server",
    description="API-Key-Free Hybrid Machine Learning & Static Analysis Platform",
    version="2.0.0"
)

cors_origins = [o.strip() for o in (os.getenv("CORS_ORIGINS") or "http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173").split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

LEGACY = {"BENIGN": "SAFE", "INSUFFICIENT EVIDENCE": "UNKNOWN", "MALWARE-ASSOCIATED": "PHISHING"}
CANON = ["SAFE", "SUSPICIOUS", "PHISHING", "UNKNOWN"]
canon = lambda v: LEGACY.get(v, v)
iso = lambda d: d.isoformat(timespec="seconds").replace("+00:00", "Z") if d else None

# Pipeline execution stages
STAGES = [
    "input",
    "validation",
    "normalization",
    "features",
    "rules",
    "threat_intel",
    "random_forest",
    "xgboost",
    "active_model",
    "shap",
    "risk",
    "verdict",
    "report"
]

_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
JOB_CACHE: Dict[str, dict] = {}


class JobTracker:
    """Manages scan progress in memory and syncs completed state to SQLite."""
    def __init__(self, pid: Optional[str], mode: str):
        self.pid = pid if (pid and _ID_PATTERN.match(pid)) else None
        self.mode = mode
        self.t0 = {}
        self.timeline = []

        if self.pid:
            initial_stages = {s: "pending" for s in STAGES}
            JOB_CACHE[self.pid] = {
                "mode": mode,
                "stages": initial_stages,
                "done": False,
                "error": None,
                "verdict": None,
                "ts": time.time()
            }

    def _sync(self, stage: str, status: str):
        if not self.pid:
            return
        if self.pid in JOB_CACHE:
            JOB_CACHE[self.pid]["stages"][stage] = status
            JOB_CACHE[self.pid]["ts"] = time.time()

    def start(self, stage: str):
        self.t0[stage] = time.time()
        self._sync(stage, "active")

    def done(self, stage: str, status: str = "done"):
        ms = int((time.time() - self.t0.get(stage, time.time())) * 1000)
        self.timeline.append({"stage": stage, "status": status, "ms": ms})
        self._sync(stage, status)

    def skip(self, stage: str):
        self.timeline.append({"stage": stage, "status": "skipped", "ms": 0})
        self._sync(stage, "skipped")

    def fail(self, stage: str, msg: str):
        self._sync(stage, "error")
        if self.pid and self.pid in JOB_CACHE:
            JOB_CACHE[self.pid].update(done=True, error=msg)
        try:
            with Session() as s:
                job = s.get(ScanJob, self.pid)
                if not job:
                    job = ScanJob(id=self.pid, mode=self.mode, stages=JOB_CACHE.get(self.pid, {}).get("stages", {}), done=True, error=msg)
                    s.add(job)
                else:
                    job.done = True
                    job.error = msg
                s.commit()
        except Exception:
            pass

    def finish(self, verdict: str):
        if self.pid and self.pid in JOB_CACHE:
            JOB_CACHE[self.pid].update(done=True, verdict=verdict)
        try:
            with Session() as s:
                job = s.get(ScanJob, self.pid)
                if not job:
                    job = ScanJob(id=self.pid, mode=self.mode, stages=JOB_CACHE.get(self.pid, {}).get("stages", {}), done=True, verdict=verdict)
                    s.add(job)
                else:
                    job.done = True
                    job.verdict = verdict
                s.commit()
        except Exception:
            pass


def save_scan(kind: str, target: str, verdict: str, result: dict) -> str:
    sid = str(uuid.uuid4())
    result["id"] = sid
    with Session() as s:
        s.add(Scan(id=sid, kind=kind, target=target, verdict=verdict, result=result))
        s.commit()
    return sid


class UrlScanRequest(BaseModel):
    url: str
    scan_id: Optional[str] = None


class ThreatImportRequest(BaseModel):
    content: str = Field(..., description="CSV or JSON raw content")
    format: str = Field("csv", description="csv | json")
    source: str = Field("Manual Upload", description="Provenance feed name")


class ModelSelectRequest(BaseModel):
    model: str = Field(..., description="random_forest | xgboost")


@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)
    TI_Importer.seed_initial_threat_intelligence()


# ---------- 1. System Health & Status Endpoints ----------

@app.get("/health")
@app.get("/api/health")
def health():
    """Health status: database, active models, local threat feed status."""
    st = P.status()
    ti_st = TI_Lookup.check_database_status()
    feed_st = TI_Feed.get_feed_status()
    try:
        with Session() as s:
            s.query(func.count(Scan.id)).scalar()
            db_ok = True
    except Exception:
        db_ok = False

    return {
        "ok": True,
        "backend": "online",
        "api_keys_required": False,
        "database": db_ok,
        "active_model": st.get("active_model", "random_forest"),
        "model_loaded": st["available"],
        "shap_available": st["models"]["random_forest"]["shap_available"],
        "models": {
            "random_forest": st["models"]["random_forest"]["available"],
            "xgboost": st["models"]["xgboost"]["available"]
        },
        "threat_intelligence": {
            "available": ti_st["available"],
            "total_records": ti_st["count"],
            "last_feed_update": feed_st.get("last_successful_update"),
            "status": "Ready (Offline Supported)" if ti_st["count"] > 0 else "Empty"
        }
    }


@app.get("/api/status")
@app.get("/api/system/status")
def system_status():
    """Detailed on-premise system status."""
    return health()


@app.get("/api/stats")
def stats():
    """Database-backed scan statistics."""
    with Session() as s:
        by = {k: 0 for k in CANON}
        for v, n in s.query(Scan.verdict, func.count(Scan.id)).group_by(Scan.verdict).all():
            c = canon(v)
            by[c] = by.get(c, 0) + n
        kinds = dict(s.query(Scan.kind, func.count(Scan.id)).group_by(Scan.kind).all())
        total = sum(by.values())
        day = s.query(func.count(Scan.id)).filter(Scan.created >= datetime.now(timezone.utc) - timedelta(hours=24)).scalar() or 0

        recent_rows = s.query(Scan).order_by(Scan.created.desc()).limit(6).all()
        recent = [
            {
                "id": x.id,
                "kind": x.kind,
                "target": x.target,
                "verdict": canon(x.verdict),
                "created": iso(x.created),
                "score": ((x.result or {}).get("risk") or {}).get("score")
            }
            for x in recent_rows
        ]

    return {
        "total": total,
        "threats": by["PHISHING"] + by["SUSPICIOUS"],
        "phishing": by["PHISHING"],
        "suspicious": by["SUSPICIOUS"],
        "safe": by["SAFE"],
        "unknown": by["UNKNOWN"],
        "url_scans": kinds.get("url", 0),
        "apk_analyses": kinds.get("apk", 0),
        "last_24h": day,
        "recent": recent
    }


@app.get("/api/progress/{pid}")
def get_progress(pid: str):
    """Retrieve scan execution progress."""
    if pid in JOB_CACHE:
        return JOB_CACHE[pid]

    with Session() as s:
        job = s.get(ScanJob, pid)
        if not job:
            raise HTTPException(404, "Scan job not found.")
        return {
            "mode": job.mode,
            "stages": job.stages,
            "done": job.done,
            "error": job.error,
            "verdict": job.verdict
        }


# ---------- 2. URL Scanning Pipeline Endpoints ----------

@app.post("/api/scan-url")
@app.post("/api/scan/url")
async def scan_url(b: UrlScanRequest):
    """Scan submitted URL locally using Rule Heuristics + Threat Feed + Active ML + SHAP."""
    tr = JobTracker(b.scan_id, "url")
    tr.start("input")
    tr.done("input")

    tr.start("validation")
    try:
        url = F.normalize(b.url)
    except ValueError as e:
        tr.fail("validation", str(e))
        raise HTTPException(400, str(e))
    tr.done("validation")

    tr.start("normalization")
    tr.done("normalization")

    tr.start("features")
    feats = F.extract(url)
    feat_tbl = F.feature_table(feats)
    indics = F.indicators(feats)
    tr.done("features")

    tr.start("rules")
    rules = F.rule_analysis(feats)
    tr.done("rules")

    tr.start("threat_intel")
    ti_res = await TI.lookup_url(url)
    ti_sum = TI.summarize(ti_res)
    tr.done("threat_intel")

    tr.start("random_forest")
    rf_res = await asyncio.to_thread(P.predict_rf, feats)
    tr.done("random_forest", "done" if rf_res.get("available") else "skipped")

    tr.start("xgboost")
    xgb_res = await asyncio.to_thread(P.predict_xgb, feats)
    tr.done("xgboost", "done" if xgb_res.get("available") else "skipped")

    tr.start("active_model")
    ml_active = P.predict_active(feats)
    tr.done("active_model", "done" if ml_active.get("available") else "skipped")

    tr.start("shap")
    shap_res = await asyncio.to_thread(P.explain_shap, feats, rf_res.get("probability")) if rf_res.get("available") else {
        "available": False,
        "kind": "shap",
        "reason": "SHAP requires a trained Random Forest model. (Status: MODEL NOT TRAINED)"
    }
    tr.done("shap", "done" if shap_res.get("available") else "skipped")

    tr.start("risk")
    risk = R.assess_risk(rules, ml_active, ti_res, is_apk=False)
    tr.done("risk")

    tr.start("verdict")
    verdict = risk["verdict"]
    tr.done("verdict")

    tr.start("report")
    r = {
        "kind": "url",
        "url": url,
        "verdict": verdict,
        "risk": risk,
        "features": feats,
        "feature_table": feat_tbl,
        "rules": rules,
        "indicators": indics,
        "threat_intel": ti_res,
        "threat_summary": ti_sum,
        "ml": {
            "available": ml_active.get("available", False),
            "probability": ml_active.get("probability"),
            "active_model_name": ml_active.get("active_model_name", "random_forest"),
            "random_forest": rf_res,
            "xgboost": xgb_res,
            "comparison": ml_active.get("comparison")
        },
        "shap": shap_res,
        "model_status": P.status(),
        "created": iso(datetime.now(timezone.utc)),
        "timeline": tr.timeline
    }
    tr.done("report")
    save_scan("url", url, verdict, r)
    tr.finish(verdict)
    return r


# ---------- 3. Android APK Static Analysis Endpoints ----------

@app.post("/api/analyze-apk")
@app.post("/api/scan/apk")
async def scan_apk(file: UploadFile = File(...), scan_id: Optional[str] = Query(None)):
    """Analyze Android APK statically with Androguard and Local Threat Intelligence."""
    tr = JobTracker(scan_id, "apk")
    tr.start("input")
    tr.done("input")

    tr.start("validation")
    mx = int(os.getenv("MAX_APK_MB") or 100) * 1024 * 1024
    if not (file.filename or "").lower().endswith(".apk"):
        tr.fail("validation", "APK required")
        raise HTTPException(400, "Please upload a file with the .apk extension.")

    data = await file.read(mx + 1)
    if len(data) > mx or data[:2] != b"PK":
        tr.fail("validation", "Invalid archive")
        raise HTTPException(400, f"Invalid or oversized APK (max {mx // 1048576} MB).")

    with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as t:
        temp_path = t.name
        t.write(data)
        t.flush()

    try:
        with zipfile.ZipFile(temp_path) as zf:
            if "AndroidManifest.xml" not in zf.namelist():
                tr.fail("validation", "Missing AndroidManifest.xml")
                raise HTTPException(400, "Archive contains no AndroidManifest.xml — not a valid Android APK.")
        tr.done("validation")

        tr.start("normalization")
        tr.done("normalization")

        tr.start("features")
        hashes = APK.file_hashes(temp_path)
        try:
            apk_data = await asyncio.to_thread(APK.analyze, temp_path)
        except Exception as e:
            tr.fail("features", str(e))
            raise HTTPException(422, f"Could not parse APK: {type(e).__name__}: {e}")
        tr.done("features")

    finally:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass

    tr.start("rules")
    sr = APK.score(apk_data)
    apk_data["static_risk"] = sr
    tr.done("rules")

    tr.start("threat_intel")
    ti_res = APK.check_apk_local_threat_intel(hashes, apk_data.get("domains", []))
    apk_data["threat_intel"] = ti_res
    apk_data["threat_summary"] = TI.summarize(ti_res)
    tr.done("threat_intel")

    tr.skip("random_forest")
    tr.skip("xgboost")
    tr.skip("active_model")
    tr.skip("shap")

    tr.start("risk")
    base_score = sr["score"]
    ti_floor = 0
    ti_mal = any(t.get("status") == "MALICIOUS" for t in ti_res)
    ti_susp = any(t.get("status") == "SUSPICIOUS" for t in ti_res)

    if ti_mal:
        ti_floor = 95
        verdict = "PHISHING"
    elif base_score >= 50 or ti_susp:
        verdict = "SUSPICIOUS"
    elif base_score <= 25 and not ti_susp:
        verdict = "SAFE"
    else:
        verdict = "UNKNOWN"

    final_score = max(base_score, ti_floor)
    apk_data["risk"] = {
        "score": final_score,
        "verdict": verdict,
        "category": "MALWARE" if ti_mal else None,
        "level": APK.risk_level(final_score),
        "confidence": "high" if ti_mal else "medium",
        "breakdown": [
            {"source": "Static Manifest & Permissions Analysis", "available": True, "value": base_score, "detail": f"{len(sr['indicators'])} risk indicator(s)"},
            {"source": "Local Threat Database (Hash & Domain lookup)", "available": True, "value": "MALICIOUS" if ti_mal else "SUSPICIOUS" if ti_susp else "CLEAN", "detail": f"{len(ti_res)} threat feed query check(s)"}
        ],
        "notes": ["Static analysis only; APK was never executed dynamically.", "No ML probability model is applied to binary APK files."]
    }
    apk_data["verdict"] = verdict
    apk_data["kind"] = "apk"
    apk_data["filename"] = file.filename
    apk_data["hashes"] = hashes
    apk_data["created"] = iso(datetime.now(timezone.utc))
    apk_data["timeline"] = tr.timeline

    tr.done("risk")
    tr.start("verdict")
    tr.done("verdict")

    tr.start("report")
    tr.done("report")

    save_scan("apk", apk_data["package"] or file.filename, verdict, apk_data)
    tr.finish(verdict)
    return apk_data


# ---------- 4. Threat Intelligence Endpoints ----------

@app.get("/api/threat-intelligence/status")
@app.get("/api/threat-intelligence/stats")
def threat_intelligence_status():
    """Retrieve status, statistics, and OpenPhish feed metadata."""
    stats_obj = TI_Lookup.get_threat_stats()
    feed_st = TI_Feed.get_feed_status()
    out = stats_obj.model_dump()
    out["feed_updater"] = feed_st
    return out


@app.post("/api/threat-intelligence/update")
async def threat_intelligence_update():
    """Trigger manual or scheduled update of the OpenPhish Community Feed."""
    res = await TI_Feed.update_openphish_feed()
    return res


@app.post("/api/threat-intelligence/import")
def threat_intel_import(req: ThreatImportRequest):
    """Import custom CSV or JSON threat intelligence feeds into the local database."""
    if req.format.lower() == "json":
        res = TI_Importer.import_json_content(req.content, source=req.source)
    else:
        res = TI_Importer.import_csv_content(req.content, source=req.source)
    return res.model_dump()


@app.get("/api/threat-intelligence/search")
def threat_intel_search(q: str = Query(..., min_length=2)):
    """Search local threat intelligence database by URL, domain, or hash."""
    return TI_Lookup.search_threat_records(q, limit=50)


# ---------- 5. Machine Learning Models & Comparison Endpoints ----------

@app.get("/api/models/status")
@app.get("/api/model/status")
def models_status():
    """Status of Random Forest and XGBoost local models."""
    return P.status()


@app.get("/api/models/compare")
@app.get("/api/model/metrics")
def models_compare():
    """Side-by-side evaluation metrics comparing Random Forest and XGBoost."""
    metrics_data = P.metrics()
    if not metrics_data:
        return {"status": "MODEL NOT TRAINED", "message": "No model evaluation metrics found. Run training/train.py."}
    return metrics_data


@app.post("/api/models/select")
def select_active_model(req: ModelSelectRequest):
    """Set active model to either 'random_forest' or 'xgboost'."""
    ok = P.set_active_model_name(req.model)
    if not ok:
        raise HTTPException(400, "Invalid model name. Choose 'random_forest' or 'xgboost'.")
    return {"success": True, "active_model": req.model}


@app.post("/api/models/train")
def train_models_endpoint(bg: BackgroundTasks):
    """Trigger local Random Forest and XGBoost training and comparison."""
    try:
        report = train_and_compare_models()
        return {"success": True, "report": report}
    except Exception as e:
        raise HTTPException(500, f"Model training failed: {e}")


@app.get("/api/explain/global")
def explain_global():
    """Global feature importances from trained models."""
    return {
        "model": P.status(),
        "importance": P.global_importance(),
        "registry": list_registered_models()
    }


# ---------- 6. Reports and History Endpoints ----------

@app.get("/api/history")
def history(q: Optional[str] = None, verdict: Optional[str] = None, kind: Optional[str] = None, limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    """Search and filter historical scan records."""
    with Session() as s:
        qs = s.query(Scan)
        if q:
            qs = qs.filter(Scan.target.ilike(f"%{q}%"))
        if kind in ("url", "apk"):
            qs = qs.filter(Scan.kind == kind)
        if verdict:
            names = [verdict] + [k for k, v in LEGACY.items() if v == verdict]
            qs = qs.filter(Scan.verdict.in_(names))
        total = qs.count()
        rows = qs.order_by(Scan.created.desc()).offset(offset).limit(limit).all()
        return {
            "total": total,
            "items": [
                {
                    "id": x.id,
                    "kind": x.kind,
                    "target": x.target,
                    "verdict": canon(x.verdict),
                    "created": iso(x.created),
                    "score": ((x.result or {}).get("risk") or {}).get("score")
                }
                for x in rows
            ]
        }


@app.get("/api/reports")
def list_reports(limit: int = 50):
    """List available scan reports."""
    return history(limit=limit)


@app.get("/api/scan/{sid}")
def get_scan(sid: str):
    """Retrieve full details of a specific scan."""
    with Session() as s:
        x = s.get(Scan, sid)
        if not x:
            raise HTTPException(404, "Scan not found.")
        r = dict(x.result or {})
        r.update(id=x.id, kind=x.kind, verdict=canon(x.verdict), created=iso(x.created))
        return r


@app.get("/api/report/{sid}/pdf")
def report_pdf(sid: str):
    """Export complete forensic PDF report for a scan."""
    with Session() as s:
        x = s.get(Scan, sid)
        if not x:
            raise HTTPException(404, "Scan not found.")
        scan_data = {
            "id": x.id,
            "kind": x.kind,
            "target": x.target,
            "verdict": canon(x.verdict),
            "created": iso(x.created),
            "result": x.result
        }
    pdf_bytes = build_pdf(scan_data)
    return Response(
        pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="phishguard-report-{sid[:8]}.pdf"'}
    )
