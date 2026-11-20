"""Independent Model Evaluation and Metrics Aggregation.

Evaluates Random Forest, CNN, BiLSTM, and Ensemble on a held-out test split.
Metrics: Accuracy, Precision, Recall, F1-score, ROC-AUC, PR-AUC, Confusion Matrix,
False Positive Rate (FPR), False Negative Rate (FNR), and Inference Latency (ms).
Outputs to ml_models/metrics/
"""
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    precision_recall_curve,
    auc,
    confusion_matrix
)

from .config import METRICS_DIR, MODEL_DIR, PROCESSED_DATA_DIR


def compute_comprehensive_metrics(y_true: List[int], y_prob: List[float], latency_ms: float, model_name: str, threshold: float = 0.5) -> Dict[str, Any]:
    """Compute complete set of evaluation metrics."""
    y_true_arr = np.array(y_true, dtype=int)
    y_prob_arr = np.array(y_prob, dtype=float)
    y_pred_arr = (y_prob_arr >= threshold).astype(int)

    # Confusion matrix: tn, fp, fn, tp
    cm = confusion_matrix(y_true_arr, y_pred_arr, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    # Rates
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    # PR-AUC
    precision_curve, recall_curve, _ = precision_recall_curve(y_true_arr, y_prob_arr)
    pr_auc_val = float(auc(recall_curve, precision_curve))

    # ROC-AUC
    try:
        roc_auc_val = float(roc_auc_score(y_true_arr, y_prob_arr))
    except Exception:
        roc_auc_val = 0.5

    return {
        "model_name": model_name,
        "evaluation_timestamp": datetime.now(timezone.utc).isoformat(),
        "threshold": threshold,
        "test_samples": len(y_true_arr),
        "benign_samples": int((y_true_arr == 0).sum()),
        "phishing_samples": int((y_true_arr == 1).sum()),
        "accuracy": round(float(accuracy_score(y_true_arr, y_pred_arr)), 4),
        "precision": round(float(precision_score(y_true_arr, y_pred_arr, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true_arr, y_pred_arr, zero_division=0)), 4),
        "f1_score": round(float(f1_score(y_true_arr, y_pred_arr, zero_division=0)), 4),
        "roc_auc": round(roc_auc_val, 4),
        "pr_auc": round(pr_auc_val, 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
        "confusion_matrix": {
            "true_negatives": int(tn),
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "true_positives": int(tp),
            "matrix": cm.tolist()
        },
        "latency_ms": round(latency_ms, 2)
    }


def save_model_metrics(model_key: str, metrics_dict: Dict[str, Any]):
    """Save metrics to ml_models/metrics/<model_key>.json."""
    METRICS_DIR.mkdir(parents=True, exist_ok=True)
    out_file = METRICS_DIR / f"{model_key}.json"
    with open(out_file, "w") as f:
        json.dump(metrics_dict, f, indent=2)


def generate_model_comparison() -> Dict[str, Any]:
    """Generate side-by-side model comparison report in ml_models/metrics/model_comparison.json."""
    comparison = {}
    for key in ["random_forest", "cnn", "bilstm", "ensemble"]:
        f = METRICS_DIR / f"{key}.json"
        if f.exists():
            try:
                with open(f, "r") as fp:
                    comparison[key] = json.load(fp)
            except Exception:
                pass

    comp_report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "models": comparison,
        "summary": "Independent evaluation on held-out test split with domain-group isolation."
    }

    out_file = METRICS_DIR / "model_comparison.json"
    with open(out_file, "w") as f:
        json.dump(comp_report, f, indent=2)

    # Also write top-level ml_models/metrics.json for backward compatibility with the dashboard
    legacy_file = MODEL_DIR / "metrics.json"
    with open(legacy_file, "w") as f:
        json.dump(comparison, f, indent=2)

    return comp_report
