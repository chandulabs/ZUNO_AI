"""Hybrid Ensemble Fusion Engine.

Combines predictions from Random Forest, Character-CNN, and Character-BiLSTM.
Uses validation-selected weighted fusion. Handles missing/unavailable models gracefully
by dynamically renormalizing weights and reporting contributing models.
"""
from typing import Dict, Any, List, Optional
import numpy as np

# Baseline validation-optimized ensemble weights
DEFAULT_WEIGHTS = {
    "random_forest": 0.40,
    "cnn": 0.35,
    "bilstm": 0.25
}


def combine_predictions(
    rf_res: Optional[Dict[str, Any]],
    cnn_res: Optional[Dict[str, Any]],
    bilstm_res: Optional[Dict[str, Any]],
    weights: Dict[str, float] = None
) -> Dict[str, Any]:
    """Fuse model predictions using weighted voting with dynamic weight normalization.
    
    If one or more models are unavailable, weights are redistributed proportionally.
    Missing models NEVER count as safe (zero probability).
    """
    weights = weights or DEFAULT_WEIGHTS
    active_models = {}
    active_weights = {}

    if rf_res and rf_res.get("available") and rf_res.get("probability") is not None:
        active_models["random_forest"] = float(rf_res["probability"])
        active_weights["random_forest"] = weights.get("random_forest", 0.40)

    if cnn_res and cnn_res.get("available") and cnn_res.get("probability") is not None:
        active_models["cnn"] = float(cnn_res["probability"])
        active_weights["cnn"] = weights.get("cnn", 0.35)

    if bilstm_res and bilstm_res.get("available") and bilstm_res.get("probability") is not None:
        active_models["bilstm"] = float(bilstm_res["probability"])
        active_weights["bilstm"] = weights.get("bilstm", 0.25)

    if not active_models:
        return {
            "available": False,
            "probability": None,
            "contributing_models": [],
            "missing_models": ["random_forest", "cnn", "bilstm"],
            "weights": {},
            "message": "NO TRAINED MODELS AVAILABLE"
        }

    # Normalize active weights so they sum to 1.0
    total_w = sum(active_weights.values())
    norm_weights = {k: v / total_w for k, v in active_weights.items()}

    ensemble_prob = sum(active_models[k] * norm_weights[k] for k in active_models)

    contributing = list(active_models.keys())
    missing = [m for m in ["random_forest", "cnn", "bilstm"] if m not in active_models]

    model_contributions = [
        {
            "model": k,
            "probability": round(active_models[k], 4),
            "effective_weight": round(norm_weights[k], 3),
            "weighted_contribution": round(active_models[k] * norm_weights[k], 4)
        }
        for k in active_models
    ]

    return {
        "available": True,
        "probability": round(float(ensemble_prob), 4),
        "contributing_models": contributing,
        "missing_models": missing,
        "effective_weights": norm_weights,
        "model_contributions": model_contributions,
        "confidence": "high" if len(contributing) >= 2 else "medium",
        "message": f"Hybrid ensemble fused from {len(contributing)} model(s)."
    }
