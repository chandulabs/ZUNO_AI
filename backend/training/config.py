"""Training and Evaluation Configuration."""
import os
import tempfile
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
ROOT_DIR = BACKEND_DIR.parent
ON_VERCEL = os.getenv("VERCEL") == "1"
DATASETS_DIR = Path(tempfile.gettempdir()) / "datasets" if ON_VERCEL else ROOT_DIR / "datasets"
RAW_DATA_DIR = DATASETS_DIR / "raw"
PROCESSED_DATA_DIR = DATASETS_DIR / "processed"
REPORTS_DATA_DIR = DATASETS_DIR / "reports"
DEFAULT_MODEL_DIR = BACKEND_DIR / "ml_models" if ON_VERCEL else ROOT_DIR / "ml_models"
MODEL_DIR = Path(os.getenv("MODEL_DIR") or DEFAULT_MODEL_DIR)
METRICS_DIR = MODEL_DIR / "metrics"

for d in [RAW_DATA_DIR, PROCESSED_DATA_DIR, REPORTS_DATA_DIR, MODEL_DIR, METRICS_DIR]:
    d.mkdir(parents=True, exist_ok=True)

RANDOM_STATE = 42
TEST_SPLIT = 0.20
VAL_SPLIT = 0.15

# Training Hyperparameters
RF_PARAMS = {
    "n_estimators": 300,
    "max_depth": 25,
    "min_samples_split": 4,
    "random_state": RANDOM_STATE,
    "n_jobs": -1
}

CNN_PARAMS = {
    "embed_dim": 64,
    "num_filters": 128,
    "dropout": 0.3,
    "lr": 0.001,
    "batch_size": 64,
    "epochs": 15,
    "early_stopping_patience": 3
}

BILSTM_PARAMS = {
    "embed_dim": 64,
    "hidden_dim": 64,
    "num_layers": 2,
    "dropout": 0.3,
    "lr": 0.001,
    "batch_size": 64,
    "epochs": 15,
    "early_stopping_patience": 3
}
