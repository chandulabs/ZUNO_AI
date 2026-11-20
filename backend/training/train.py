"""Machine Learning Model Training and Evaluation Pipeline.

Trains, evaluates, and compares two models:
  A. Random Forest Classifier (Scikit-Learn)
  B. XGBoost Classifier (XGBoost)

Both models use the identical feature extraction pipeline and are trained/evaluated
on stratified, domain-isolated splits (Train, Validation, Test) without data leakage.
The best model is selected based strictly on validation-set performance.
Artifacts saved via Joblib.
"""
import argparse
import json
import time
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier

from .config import (
    MODEL_DIR,
    METRICS_DIR,
    PROCESSED_DATA_DIR,
    RAW_DATA_DIR,
    RANDOM_STATE
)
from .dataset_loader import process_dataset_pipeline
from .evaluate import compute_comprehensive_metrics, save_model_metrics
from .model_registry import register_model
from detection.features import extract, NAMES, FEATURE_INFO


def train_and_compare_models(csv_path: Path = None, dataset_version: str = "v1.0"):
    print("=" * 70)
    print("PHISHGUARD AI — HYBRID MACHINE LEARNING TRAINING PIPELINE")
    print("Random Forest vs XGBoost Comparison (API-Free, On-Premise)")
    print("=" * 70)

    # 1. Dataset Preprocessing & Ingestion
    train_file = PROCESSED_DATA_DIR / "train.csv"
    val_file = PROCESSED_DATA_DIR / "val.csv"
    test_file = PROCESSED_DATA_DIR / "test.csv"

    if csv_path or not (train_file.exists() and test_file.exists()):
        src_csv = csv_path or (RAW_DATA_DIR / "urls.csv")
        if not src_csv.exists():
            from .build_dataset import create_initial_raw_dataset
            print(f"Creating verified raw dataset at {src_csv}...")
            create_initial_raw_dataset()
        print(f"Processing dataset pipeline on {src_csv}...")
        report = process_dataset_pipeline(src_csv, dataset_version=dataset_version)
        print(f"Dataset splits: {report['splits']['train']['count']} train, "
              f"{report['splits']['val']['count']} val, "
              f"{report['splits']['test']['count']} test.")

    train_df = pd.read_csv(train_file)
    val_df = pd.read_csv(val_file)
    test_df = pd.read_csv(test_file)

    # 2. Extract structured features
    print(f"\nExtracting {len(NAMES)} lexical & structural features...")
    
    def extract_features(df):
        rows = [extract(str(u)) for u in df["url"]]
        return pd.DataFrame(rows)[NAMES]

    X_train = extract_features(train_df)
    y_train = train_df["label"].values

    X_val = extract_features(val_df)
    y_val = val_df["label"].values

    X_test = extract_features(test_df)
    y_test = test_df["label"].values

    # 3. Model Definitions
    rf_model = RandomForestClassifier(
        n_estimators=300,
        max_depth=25,
        min_samples_split=4,
        random_state=RANDOM_STATE,
        n_jobs=-1
    )

    xgb_model = XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=RANDOM_STATE,
        eval_metric="logloss",
        n_jobs=-1
    )

    models = {
        "random_forest": rf_model,
        "xgboost": xgb_model
    }

    val_scores = {}
    test_metrics = {}

    # 4. Train and Evaluate each model
    for name, model in models.items():
        print(f"\n[Training] {name.replace('_', ' ').title()}...")
        t0 = time.time()
        model.fit(X_train, y_train)
        fit_time = time.time() - t0
        print(f"Trained {name} in {fit_time:.2f}s.")

        # Validation set evaluation (used for model selection)
        val_probs = model.predict_proba(X_val)[:, 1]
        val_pred = (val_probs >= 0.5).astype(int)
        from sklearn.metrics import f1_score, roc_auc_score
        val_f1 = float(f1_score(y_val, val_pred, zero_division=0))
        val_roc = float(roc_auc_score(y_val, val_probs))
        val_scores[name] = {"f1": val_f1, "roc_auc": val_roc, "score": (val_f1 + val_roc) / 2}
        print(f"Validation F1: {val_f1:.4f} | Validation ROC-AUC: {val_roc:.4f}")

        # Test set evaluation (held-out performance)
        t_eval = time.time()
        test_probs = model.predict_proba(X_test)[:, 1]
        latency_ms = ((time.time() - t_eval) / len(test_df)) * 1000

        m = compute_comprehensive_metrics(
            y_true=y_test,
            y_prob=test_probs,
            latency_ms=latency_ms,
            model_name=name.replace('_', ' ').title(),
            threshold=0.50
        )
        test_metrics[name] = m
        print(f"Test Accuracy: {m['accuracy']*100:.2f}% | Precision: {m['precision']*100:.2f}% | Recall: {m['recall']*100:.2f}% | F1: {m['f1_score']:.4f}")

        # Save model artifact using Joblib
        art_path = MODEL_DIR / f"{name}.joblib"
        joblib.dump(model, art_path)
        print(f"Saved artifact to {art_path}")

        # Save individual metrics
        save_model_metrics(name, m)
        with open(MODEL_DIR / f"{name}_metrics.json", "w") as f:
            json.dump(m, f, indent=2)

        # Register in model registry
        register_model(
            name=name,
            file_path=art_path,
            version="2.0.0",
            framework="scikit-learn" if name == "random_forest" else "xgboost",
            metrics=m,
            dataset_version=dataset_version,
            approved=True
        )

    # 5. Best Model Selection based strictly on Validation performance
    best_model_name = max(val_scores, key=lambda k: val_scores[k]["score"])
    print(f"\n>>> Best Model Selected (by validation performance): {best_model_name.upper()} <<<")

    model_selection_info = {
        "active_model": best_model_name,
        "selected_at": time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime()),
        "selection_metric": "Validation F1 + ROC-AUC Mean",
        "validation_scores": val_scores,
        "available_models": list(models.keys())
    }
    with open(MODEL_DIR / "active_model.json", "w") as f:
        json.dump(model_selection_info, f, indent=2)

    # 6. Save Feature Metadata
    with open(MODEL_DIR / "feature_metadata.json", "w") as f:
        json.dump({
            "feature_names": NAMES,
            "feature_info": FEATURE_INFO,
            "num_features": len(NAMES)
        }, f, indent=2)

    # 7. Generate Side-by-Side Comparison Report
    comparison_report = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime()),
        "active_model": best_model_name,
        "models": {
            "random_forest": test_metrics.get("random_forest"),
            "xgboost": test_metrics.get("xgboost")
        },
        "comparison_summary": {
            "winner_validation": best_model_name,
            "validation_scores": val_scores,
            "metrics_comparison": {
                metric: {
                    "random_forest": test_metrics["random_forest"].get(metric),
                    "xgboost": test_metrics["xgboost"].get(metric)
                }
                for metric in ["accuracy", "precision", "recall", "f1_score", "roc_auc", "pr_auc", "latency_ms"]
            }
        }
    }

    with open(METRICS_DIR / "model_comparison.json", "w") as f:
        json.dump(comparison_report, f, indent=2)
    with open(MODEL_DIR / "metrics.json", "w") as f:
        json.dump(comparison_report["models"], f, indent=2)

    print(f"\nModel comparison report saved to {METRICS_DIR / 'model_comparison.json'}")
    return comparison_report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", default=None, help="Path to raw dataset CSV")
    parser.add_argument("--version", default="v1.0", help="Dataset version tag")
    args = parser.parse_args()
    csv_p = Path(args.csv) if args.csv else None
    train_and_compare_models(csv_path=csv_p, dataset_version=args.version)
