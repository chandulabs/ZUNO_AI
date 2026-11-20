"""Test End-to-End URL and APK Scanning Pipelines."""
import sys
import asyncio
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from detection.orchestrator import scan_url_pipeline
from threat_intelligence import lookup as TI_Lookup

async def main():
    # 1. Threat Intel Check
    st = TI_Lookup.get_threat_stats()
    print(f"[Threat Intel] Records: {st.total_records}, Available: {st.available}")

    # 2. URL Scan
    url = "http://secure-paypal-login-verify.com/account/login.php"
    print(f"\n[Scanning URL] {url}...")
    res = await scan_url_pipeline(url, tracker_cb=lambda s, st: print(f"  -> [{s}]: {st}"))
    print("\n--- Scan Results ---")
    print(f"Verdict: {res['verdict']}")
    print(f"Risk Score: {res['risk']['score']}/100")
    print(f"Active Model: {res['ml']['active_model_name']}")
    print(f"Random Forest Prob: {res['ml']['random_forest']['probability']}")
    print(f"XGBoost Prob: {res['ml']['xgboost']['probability']}")
    print(f"Threat Intel Status: {res['threat_summary']['status']}")
    print(f"SHAP Available: {res['shap']['available']}")
    if res['shap']['available']:
        print(f"SHAP Summary: {res['shap']['summary']}")

    # 3. Test Safe Benign URL
    benign_url = "https://en.wikipedia.org/wiki/Phishing"
    print(f"\n[Scanning Benign URL] {benign_url}...")
    res_b = await scan_url_pipeline(benign_url)
    print(f"Benign URL Verdict: {res_b['verdict']}")
    print(f"Benign Risk Score: {res_b['risk']['score']}/100")
    print(f"Benign Active Model Prob: {res_b['ml']['probability']}")

    print("\nSUCCESS: All pipeline components executed smoothly!")

if __name__ == "__main__":
    asyncio.run(main())
