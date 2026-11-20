"""Detection Orchestrator.

Orchestrates the complete multi-layer URL scanning pipeline:
  Input -> Validation -> Normalization -> Features -> Rules -> Threat Intel
  -> Random Forest -> XGBoost -> Character-CNN -> Character-BiLSTM -> Hybrid Ensemble
  -> Active Model Selection -> SHAP TreeExplainer & Neural Explainability -> Risk Assessment -> Verdict
"""
from typing import Dict, Any, Callable
from .features import normalize, extract, rule_analysis, feature_table, indicators
from .predict import predict_rf, predict_xgb, predict_active, explain_shap
from .ensemble import combine_predictions
from .risk import assess_risk
from threat_intelligence import adapters as TI

try:
    from deep_learning.predict import predict_cnn, predict_bilstm, explain_dl
except ImportError:
    predict_cnn = lambda u: {"available": False, "probability": None, "message": "DL module unavailable"}
    predict_bilstm = lambda u: {"available": False, "probability": None, "message": "DL module unavailable"}
    explain_dl = lambda u: {"cnn": {"available": False}, "bilstm": {"available": False}}


async def scan_url_pipeline(raw_url: str, tracker_cb: Callable[[str, str], None] = None) -> Dict[str, Any]:
    """Execute complete on-premise URL scanning pipeline."""
    def track(stage: str, status: str = "done"):
        if tracker_cb:
            tracker_cb(stage, status)

    # 1. Input
    track("input", "active")
    track("input", "done")

    # 2. Validation & Normalization
    track("validation", "active")
    url = normalize(raw_url)
    track("validation", "done")

    track("normalization", "active")
    track("normalization", "done")

    # 3. Feature Extraction
    track("features", "active")
    feats = extract(url)
    feat_tbl = feature_table(feats)
    indics = indicators(feats)
    track("features", "done")

    # 4. Rule-based Detection
    track("rules", "active")
    rules = rule_analysis(feats)
    track("rules", "done")

    # 5. Local Threat Intelligence Lookup
    track("threat_intel", "active")
    ti_results = await TI.lookup_url(url)
    ti_summary = TI.summarize(ti_results)
    track("threat_intel", "done")

    # 6. Random Forest Prediction
    track("random_forest", "active")
    rf_res = predict_rf(feats)
    track("random_forest", "done" if rf_res.get("available") else "skipped")

    # 7. XGBoost Prediction
    track("xgboost", "active")
    xgb_res = predict_xgb(feats)
    track("xgboost", "done" if xgb_res.get("available") else "skipped")

    # 8. Character-CNN Prediction
    track("cnn", "active")
    try:
        cnn_res = predict_cnn(url)
    except Exception as e:
        cnn_res = {"available": False, "probability": None, "message": str(e)}
    track("cnn", "done" if cnn_res.get("available") else "skipped")

    # 9. Character-BiLSTM Prediction
    track("bilstm", "active")
    try:
        bilstm_res = predict_bilstm(url)
    except Exception as e:
        bilstm_res = {"available": False, "probability": None, "message": str(e)}
    track("bilstm", "done" if bilstm_res.get("available") else "skipped")

    # 10. Hybrid Ensemble Fusion
    track("ensemble", "active")
    ensemble_res = combine_predictions(rf_res, cnn_res, bilstm_res)
    track("ensemble", "done" if ensemble_res.get("available") else "skipped")

    # 11. Active Model Selection
    track("active_model", "active")
    ml_active = predict_active(feats)
    track("active_model", "done" if ml_active.get("available") else "skipped")

    # 12. SHAP & Neural Explainability
    track("shap", "active")
    shap_res = explain_shap(feats, rf_res.get("probability")) if rf_res.get("available") else {
        "available": False,
        "kind": "shap",
        "reason": "SHAP requires a trained Random Forest model. (Status: MODEL NOT TRAINED)"
    }
    try:
        dl_explain = explain_dl(url)
    except Exception:
        dl_explain = {"cnn": {"available": False}, "bilstm": {"available": False}}
    track("shap", "done" if shap_res.get("available") else "skipped")

    # 13. Risk Assessment
    track("risk", "active")
    risk = assess_risk(rules, ml_active, ti_results, is_apk=False, ensemble_result=ensemble_res)
    track("risk", "done")

    # 14. Final Verdict
    track("verdict", "active")
    verdict = risk["verdict"]
    track("verdict", "done")

    # 15. Report Packaging
    track("report", "active")
    track("report", "done")

    return {
        "kind": "url",
        "url": url,
        "verdict": verdict,
        "risk": risk,
        "features": feats,
        "feature_table": feat_tbl,
        "rules": rules,
        "indicators": indics,
        "threat_intel": ti_results,
        "threat_summary": ti_summary,
        "ml": {
            "available": ml_active.get("available", False) or ensemble_res.get("available", False),
            "probability": ensemble_res.get("probability") if ensemble_res.get("available") else ml_active.get("probability"),
            "active_model_name": ml_active.get("active_model_name", "random_forest"),
            "active_model": ml_active.get("primary"),
            "random_forest": rf_res,
            "xgboost": xgb_res,
            "cnn": cnn_res,
            "bilstm": bilstm_res,
            "ensemble": ensemble_res,
            "comparison": ml_active.get("comparison")
        },
        "shap": shap_res,
        "neural_explain": dl_explain
    }
