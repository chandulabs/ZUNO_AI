"""Model Artifact Registry and Manifest Management.

Tracks versioned model weights, SHA-256 integrity checksums, evaluation metrics,
and approval status for server-side inference.
"""
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional

from .config import MODEL_DIR

MANIFEST_FILE = MODEL_DIR / "manifest.json"


def compute_sha256(file_path: Path) -> str:
    """Compute SHA-256 checksum of a model file."""
    if not file_path.exists():
        return ""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_manifest() -> Dict[str, Any]:
    """Load model registry manifest."""
    if not MANIFEST_FILE.exists():
        return {
            "registry_version": "1.0",
            "last_updated": None,
            "models": {}
        }
    try:
        with open(MANIFEST_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {"registry_version": "1.0", "last_updated": None, "models": {}}


def save_manifest(manifest: Dict[str, Any]):
    """Persist model registry manifest to disk."""
    manifest["last_updated"] = datetime.now(timezone.utc).isoformat()
    with open(MANIFEST_FILE, "w") as f:
        json.dump(manifest, f, indent=2)


def register_model(
    name: str,
    file_path: Path,
    version: str,
    framework: str,
    metrics: Dict[str, Any],
    dataset_version: str = "v1.0",
    feature_schema_version: str = "2.0",
    approved: bool = True
) -> Dict[str, Any]:
    """Register or update a model artifact in the manifest with checksum verification."""
    checksum = compute_sha256(file_path)
    entry = {
        "name": name,
        "version": version,
        "file_name": file_path.name,
        "file_path": str(file_path),
        "sha256": checksum,
        "framework": framework,
        "training_timestamp": datetime.now(timezone.utc).isoformat(),
        "dataset_version": dataset_version,
        "feature_schema_version": feature_schema_version,
        "metrics": metrics,
        "approved": approved,
        "available": file_path.exists()
    }

    manifest = load_manifest()
    manifest["models"][name] = entry
    save_manifest(manifest)
    return entry


def verify_model_integrity(name: str) -> Dict[str, Any]:
    """Verify that the model file exists and matches the registered SHA-256 checksum."""
    manifest = load_manifest()
    entry = manifest.get("models", {}).get(name)
    if not entry:
        return {"valid": False, "reason": f"Model '{name}' not found in registry."}

    p = Path(entry["file_path"])
    if not p.exists():
        return {"valid": False, "reason": f"File '{p.name}' does not exist on disk."}

    current_hash = compute_sha256(p)
    if current_hash != entry["sha256"]:
        return {
            "valid": False,
            "reason": f"Checksum mismatch for {name}. Registered {entry['sha256']}, found {current_hash}."
        }

    return {"valid": True, "model": entry}


def list_registered_models() -> Dict[str, Any]:
    """Return all registered models with their current availability and status."""
    manifest = load_manifest()
    out = {}
    for name, entry in manifest.get("models", {}).items():
        p = Path(entry.get("file_path", ""))
        verified = verify_model_integrity(name)
        out[name] = {
            "name": name,
            "version": entry.get("version"),
            "framework": entry.get("framework"),
            "approved": entry.get("approved", False),
            "available": p.exists() and verified["valid"],
            "sha256": entry.get("sha256"),
            "training_timestamp": entry.get("training_timestamp"),
            "metrics": entry.get("metrics"),
            "integrity_status": "VALID" if verified["valid"] else verified.get("reason", "INVALID")
        }
    return out
