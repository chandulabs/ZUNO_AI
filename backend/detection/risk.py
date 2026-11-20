"""Centralized Risk Assessment Engine.

Fuses:
  1. Rule-based lexical and structural indicators
  2. Local Threat Intelligence database hits (OpenPhish / Local feeds)
  3. Machine Learning predictions (Active Model: Random Forest or XGBoost)

Produces a calibrated risk score (0-100), transparent breakdown, and four-state verdict:
  - SAFE: High confidence benign indicators across both ML and rules, with no threat feed hits.
  - SUSPICIOUS: Elevated risk signals (heuristics, high probability, or suspicious domain feed hit).
  - PHISHING: Conclusive evidence (exact threat intelligence hit, or high ML prob + strong rules).
  - UNKNOWN: Insufficient evidence available (missing models, unverified targets).
"""
from typing import Dict, Any, List, Optional


def assess_risk(
    rules: Dict[str, Any],
    ml_result: Dict[str, Any],
    threat_intel: List[Dict[str, Any]],
    is_apk: bool = False,
    ensemble_result: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Assess overall risk and determine final verdict."""
    breakdown = []
    notes = []

    # 1. Rule-based Component
    rs = rules.get("score", 0)
    rule_triggers = rules.get("triggered", [])
    breakdown.append({
        "source": "Rule-Based Heuristic Analysis",
        "available": True,
        "value": rs,
        "detail": f"{len(rule_triggers)} indicator(s) triggered (weighted score: {rs}/100)"
    })

    # 2. Machine Learning Component (Hybrid Ensemble & Active Model)
    ensemble_available = bool(ensemble_result and ensemble_result.get("available") and ensemble_result.get("probability") is not None)
    ml_available = ml_result.get("available", False)
    ml_prob = ml_result.get("probability")
    active_name = ml_result.get("active_model_name", "Random Forest").replace("_", " ").title()

    if ensemble_available:
        ens_prob = float(ensemble_result["probability"])
        ens_s = ens_prob * 100.0
        contribs = ", ".join(ensemble_result.get("contributing_models", []))
        breakdown.append({
            "source": "Hybrid AI Ensemble (RF + CNN + BiLSTM)",
            "available": True,
            "value": round(ens_s, 1),
            "detail": f"Fused ensemble probability: {ens_s:.1f}% malicious (models: {contribs})"
        })
        eff_prob = ens_prob
        score = 0.30 * rs + 0.70 * ens_s
    elif ml_available and ml_prob is not None:
        mls = ml_prob * 100.0
        breakdown.append({
            "source": f"Machine Learning ({active_name})",
            "available": True,
            "value": round(mls, 1),
            "detail": f"Model probability: {mls:.1f}% malicious"
        })
        eff_prob = ml_prob
        score = 0.30 * rs + 0.70 * mls
    else:
        eff_prob = None
        score = 0.80 * rs  # Capped heuristic score when ML is absent
        breakdown.append({
            "source": "Machine Learning",
            "available": False,
            "value": None,
            "detail": "MODEL NOT TRAINED - ML prediction was not computed"
        })
        notes.append("No active machine learning model was available; evaluation relied on heuristic rules and local threat feeds.")

    # 3. Threat Intelligence Component
    ti_floor = 0
    ti_reasons = []
    ti_category = None
    ti_exact_match = False
    ti_domain_match = False
    ti_usable_count = 0

    for item in threat_intel:
        st = item.get("status")
        match_type = item.get("match_type")
        is_dom = item.get("is_domain_match", False)

        is_usable = st in ("MALICIOUS", "SUSPICIOUS", "NO_MATCH")
        if is_usable:
            ti_usable_count += 1

        breakdown.append({
            "source": f"Local Threat Intelligence ({item.get('source', 'Local DB')})",
            "available": is_usable,
            "value": st,
            "detail": item.get("message") or f"Feed status: {st}"
        })

        if st == "MALICIOUS":
            if is_dom or match_type == "domain":
                ti_domain_match = True
                ti_floor = max(ti_floor, 80)
                ti_reasons.append(f"Domain is listed in local threat feed ({item.get('feed_source', 'OpenPhish')})")
                ti_category = item.get("category", "phishing")
            else:
                ti_exact_match = True
                ti_floor = max(ti_floor, 98)
                ti_reasons.append(f"Exact URL match in local threat intelligence ({item.get('feed_source', 'OpenPhish')})")
                ti_category = item.get("category", "phishing")

        elif st == "SUSPICIOUS":
            ti_floor = max(ti_floor, 60)
            ti_reasons.append(f"Target flagged as suspicious in local feed ({item.get('feed_source', 'Local')})")

    if ti_floor > score:
        score = ti_floor
        breakdown.append({
            "source": "Threat Intelligence Floor",
            "available": True,
            "value": ti_floor,
            "detail": "; ".join(ti_reasons)
        })

    final_score = int(round(min(100, max(0, score))))
    has_ml = ml_available or ensemble_available

    # 4. Verdict Determination
    if ti_exact_match:
        verdict = "PHISHING"
        confidence = "high"
        notes.append("Conclusive match found in local threat intelligence database.")
    elif ti_domain_match:
        if final_score >= 80 or (eff_prob is not None and eff_prob >= 0.65):
            verdict = "PHISHING"
        else:
            verdict = "SUSPICIOUS"
        confidence = "high"
        notes.append("Parent domain is recorded as malicious in local threat intelligence feeds.")
    elif final_score >= 70 and eff_prob is not None and eff_prob >= 0.70:
        verdict = "PHISHING"
        confidence = "high" if has_ml else "medium"
        notes.append("High probability of credential phishing detected by machine learning and structural heuristics.")
    elif final_score >= 40:
        verdict = "SUSPICIOUS"
        confidence = "medium"
        notes.append("Elevated risk signals detected. Exercise caution before submitting credentials.")
    elif final_score < 40 and has_ml and ti_usable_count > 0:
        verdict = "SAFE"
        confidence = "high"
        notes.append("No malicious indicators found across local ML and threat feeds. (Absence of evidence is not an absolute guarantee).")
    else:
        verdict = "UNKNOWN"
        confidence = "low"
        notes.append("Insufficient evidence available from local models and threat intelligence to confirm safety.")

    return {
        "score": final_score,
        "verdict": verdict,
        "category": ti_category or ("MALWARE" if is_apk and verdict == "PHISHING" else "phishing" if verdict == "PHISHING" else None),
        "confidence": confidence,
        "ml_available": has_ml,
        "exact_ti_match": ti_exact_match,
        "domain_ti_match": ti_domain_match,
        "breakdown": breakdown,
        "notes": notes,
        "method": f"Multi-layered evaluation (Rules + Local Threat Intelligence + {'Hybrid Ensemble' if ensemble_available else active_name})"
    }
