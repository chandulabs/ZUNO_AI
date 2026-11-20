"""Machine Learning Prediction and Explainability Engine.

Supports:
  1. Random Forest Classifier (Scikit-Learn) with SHAP TreeExplainer
  2. XGBoost Classifier (XGBoost)
  3. Dynamic active model selection and side-by-side comparison.

All inference runs 100% locally on-premise without external APIs or cloud dependencies.
"""
import os
import json
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
import joblib
import numpy as np
import pandas as pd

from .features import NAMES, FEATURE_INFO, describe

_BACKEND = Path(__file__).resolve().parents[1]


def model_dir() -> Path:
    p = Path(os.getenv("MODEL_DIR") or (_BACKEND.parent / "ml_models"))
    return p if p.is_absolute() else (_BACKEND / p).resolve()


_model_cache = {
    "rf": None,
    "rf_mtime": None,
    "rf_err": None,
    "xgb": None,
    "xgb_mtime": None,
    "xgb_err": None,
    "explainer": None
}


def get_active_model_name() -> str:
    """Read the currently configured active model ('random_forest' or 'xgboost')."""
    cfg_file = model_dir() / "active_model.json"
    if cfg_file.exists():
        try:
            with open(cfg_file, "r") as f:
                data = json.load(f)
                return data.get("active_model", "random_forest")
        except Exception:
            pass
    return "random_forest"


def set_active_model_name(name: str) -> bool:
    """Set the active model for primary predictions."""
    if name not in ("random_forest", "xgboost"):
        return False
    cfg_file = model_dir() / "active_model.json"
    data = {}
    if cfg_file.exists():
        try:
            with open(cfg_file, "r") as f:
                data = json.load(f)
        except Exception:
            pass
    data["active_model"] = name
    with open(cfg_file, "w") as f:
        json.dump(data, f, indent=2)
    return True


def load_rf() -> Tuple[Optional[Any], Optional[str]]:
    """Load Random Forest model artifact."""
    p = model_dir() / "random_forest.joblib"
    if not p.exists():
        return None, "Model file 'random_forest.joblib' not found. Run training/train.py."
    mt = p.stat().st_mtime
    if _model_cache["rf"] is not None and _model_cache["rf_mtime"] == mt:
        return _model_cache["rf"], None
    try:
        m = joblib.load(p)
        _model_cache["rf"] = m
        _model_cache["rf_mtime"] = mt
        _model_cache["rf_err"] = None
        return m, None
    except Exception as e:
        err = f"Failed to load Random Forest: {e}"
        _model_cache["rf_err"] = err
        return None, err


def load_xgb() -> Tuple[Optional[Any], Optional[str]]:
    """Load XGBoost model artifact."""
    p = model_dir() / "xgboost.joblib"
    if not p.exists():
        return None, "Model file 'xgboost.joblib' not found. Run training/train.py."
    mt = p.stat().st_mtime
    if _model_cache["xgb"] is not None and _model_cache["xgb_mtime"] == mt:
        return _model_cache["xgb"], None
    try:
        m = joblib.load(p)
        _model_cache["xgb"] = m
        _model_cache["xgb_mtime"] = mt
        _model_cache["xgb_err"] = None
        return m, None
    except Exception as e:
        err = f"Failed to load XGBoost: {e}"
        _model_cache["xgb_err"] = err
        return None, err


def metrics() -> Optional[Dict[str, Any]]:
    """Retrieve evaluation metrics for Random Forest and XGBoost."""
    p = model_dir() / "metrics" / "model_comparison.json"
    if p.exists():
        try:
            with open(p, "r") as f:
                return json.load(f)
        except Exception:
            pass
    legacy = model_dir() / "metrics.json"
    if legacy.exists():
        try:
            with open(legacy, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return None


def status() -> Dict[str, Any]:
    """Report status of all local machine learning models."""
    rf_m, rf_err = load_rf()
    xgb_m, xgb_err = load_xgb()
    active = get_active_model_name()

    try:
        import shap  # noqa: F401
        shap_ok = True
    except Exception:
        shap_ok = False

    rf_available = rf_m is not None
    xgb_available = xgb_m is not None

    mt = metrics() or {}
    rf_metrics = mt.get("models", {}).get("random_forest") if "models" in mt else mt.get("random_forest")
    xgb_metrics = mt.get("models", {}).get("xgboost") if "models" in mt else mt.get("xgboost")

    return {
        "available": rf_available or xgb_available,
        "active_model": active,
        "models": {
            "random_forest": {
                "name": "Random Forest",
                "available": rf_available,
                "status": "LOADED" if rf_available else "MODEL NOT TRAINED",
                "detail": rf_err or "300 decision trees, impurity-based feature split",
                "metrics": rf_metrics,
                "shap_available": shap_ok and rf_available
            },
            "xgboost": {
                "name": "XGBoost",
                "available": xgb_available,
                "status": "LOADED" if xgb_available else "MODEL NOT TRAINED",
                "detail": xgb_err or "Gradient boosted decision trees (learning_rate=0.05)",
                "metrics": xgb_metrics
            }
        },
        "model_dir": str(model_dir()),
        "feature_count": len(NAMES),
        "message": "Local ML Models Active" if (rf_available or xgb_available) else "MODELS NOT TRAINED"
    }


def predict_rf(f: dict) -> Dict[str, Any]:
    """Inference for Random Forest model."""
    m, err = load_rf()
    if m is None:
        return {"available": False, "probability": None, "message": "MODEL NOT TRAINED", "detail": err}
    x = pd.DataFrame([[f.get(n, 0) for n in NAMES]], columns=NAMES)
    classes = list(m.classes_)
    prob = float(m.predict_proba(x)[0][classes.index(1)]) if 1 in classes else float(m.predict_proba(x)[0][-1])
    return {
        "available": True,
        "probability": round(prob, 4),
        "model": "random_forest",
        "label": "Random Forest",
        "message": "Inference successful"
    }


def predict_xgb(f: dict) -> Dict[str, Any]:
    """Inference for XGBoost model."""
    m, err = load_xgb()
    if m is None:
        return {"available": False, "probability": None, "message": "MODEL NOT TRAINED", "detail": err}
    x = pd.DataFrame([[f.get(n, 0) for n in NAMES]], columns=NAMES)
    classes = list(m.classes_)
    prob = float(m.predict_proba(x)[0][classes.index(1)]) if 1 in classes else float(m.predict_proba(x)[0][-1])
    return {
        "available": True,
        "probability": round(prob, 4),
        "model": "xgboost",
        "label": "XGBoost",
        "message": "Inference successful"
    }


def predict_active(f: dict) -> Dict[str, Any]:
    """Run inference on the configured active model, while computing both for comparison."""
    active = get_active_model_name()
    rf_res = predict_rf(f)
    xgb_res = predict_xgb(f)

    chosen = rf_res if active == "random_forest" else xgb_res
    if not chosen.get("available"):
        # Fallback to whichever model is available
        chosen = xgb_res if (active == "random_forest" and xgb_res.get("available")) else rf_res

    return {
        "active_model_name": active,
        "primary": chosen,
        "available": chosen.get("available", False),
        "probability": chosen.get("probability"),
        "comparison": {
            "random_forest": rf_res,
            "xgboost": xgb_res
        }
    }


def global_importance() -> Dict[str, Any]:
    """Impurity-based feature importance of the trained Random Forest and XGBoost."""
    rf_m, _ = load_rf()
    xgb_m, _ = load_xgb()

    rf_imp = []
    if rf_m is not None and hasattr(rf_m, "feature_importances_"):
        rf_imp = sorted(
            [{"feature": n, "label": FEATURE_INFO[n]["label"], "importance": round(float(v), 4)}
             for n, v in zip(NAMES, rf_m.feature_importances_)],
            key=lambda r: -r["importance"]
        )

    xgb_imp = []
    if xgb_m is not None and hasattr(xgb_m, "feature_importances_"):
        xgb_imp = sorted(
            [{"feature": n, "label": FEATURE_INFO[n]["label"], "importance": round(float(v), 4)}
             for n, v in zip(NAMES, xgb_m.feature_importances_)],
            key=lambda r: -r["importance"]
        )

    return {
        "available": bool(rf_imp or xgb_imp),
        "random_forest": rf_imp,
        "xgboost": xgb_imp,
        "features": rf_imp  # default view
    }


def explain_shap(f: dict, prob: Optional[float] = None) -> dict:
    """SHAP TreeExplainer feature contributions for the Random Forest model."""
    m, err = load_rf()
    if m is None:
        return {
            "available": False,
            "kind": "shap",
            "reason": "SHAP requires a trained Random Forest model. (Status: MODEL NOT TRAINED)"
        }

    try:
        import shap
    except ImportError:
        return {"available": False, "kind": "shap", "reason": "SHAP library is not installed."}

    if _model_cache["explainer"] is None:
        _model_cache["explainer"] = shap.TreeExplainer(m)
    exp = _model_cache["explainer"]

    x = pd.DataFrame([[f.get(n, 0) for n in NAMES]], columns=NAMES)

    try:
        vals = exp(x)
        if len(vals.values.shape) == 3:
            sh = vals.values[0, :, 1]
            base = float(vals.base_values[0][1])
        else:
            sh = vals.values[0]
            base = float(vals.base_values[0]) if hasattr(vals.base_values, "__len__") else float(vals.base_values)
    except Exception as e:
        return {"available": False, "kind": "shap", "reason": f"SHAP computation error: {e}"}

    rows = []
    for n, v in zip(NAMES, sh):
        val = f.get(n, 0)
        rows.append({
            "feature": n,
            "label": FEATURE_INFO[n]["label"],
            "value": val,
            "shap": round(float(v), 4),
            "description": describe(n, val),
            "meaning": "Pushes prediction toward phishing" if v > 0 else "Pushes prediction toward benign" if v < 0 else "Neutral"
        })

    pos = sorted([r for r in rows if r["shap"] > 0], key=lambda r: -r["shap"])
    neg = sorted([r for r in rows if r["shap"] < 0], key=lambda r: r["shap"])

    summary = (
        f"SHAP TreeExplainer: {len(pos)} feature(s) increased phishing risk, "
        f"while {len(neg)} feature(s) contributed toward benign classification."
    )

    return {
        "available": True,
        "kind": "shap",
        "base_value": round(base, 4),
        "probability": prob,
        "contributions": rows,
        "top_positive": pos[:6],
        "top_negative": neg[:6],
        "summary": summary
    }
