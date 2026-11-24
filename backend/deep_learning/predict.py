"""Deep Learning Model Management and Inference for CNN and BiLSTM.

Loads trained PyTorch artifacts at startup, performs local inference,
and computes real character-level explainability.
"""
import os
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
import torch

from .vocabulary import encode_url, DEFAULT_MAX_LEN
from .cnn_model import CharCNN
from .bilstm_model import CharBiLSTM
from .explain import explain_neural_prediction

_BACKEND = Path(__file__).resolve().parents[1]


def get_model_dir() -> Path:
    default_dir = _BACKEND / "ml_models" if os.getenv("VERCEL") else _BACKEND.parent / "ml_models"
    p = Path(os.getenv("MODEL_DIR") or default_dir)
    return p if p.is_absolute() else (_BACKEND / p).resolve()


_dl_cache = {
    "cnn": None,
    "bilstm": None,
    "cnn_err": None,
    "bilstm_err": None
}


def load_cnn() -> Tuple[Optional[CharCNN], Optional[str]]:
    """Load character-level CNN model checkpoint."""
    if _dl_cache["cnn"] is not None:
        return _dl_cache["cnn"], None
    if _dl_cache["cnn_err"] is not None:
        return None, _dl_cache["cnn_err"]

    pt_path = get_model_dir() / "cnn_model.pt"
    if not pt_path.exists():
        return None, "Checkpoint cnn_model.pt not found."

    try:
        model = CharCNN()
        state = torch.load(pt_path, map_location="cpu")
        model.load_state_dict(state)
        model.eval()
        _dl_cache["cnn"] = model
        return model, None
    except Exception as e:
        err = f"Failed to load CNN model: {e}"
        _dl_cache["cnn_err"] = err
        return None, err


def load_bilstm() -> Tuple[Optional[CharBiLSTM], Optional[str]]:
    """Load character-level BiLSTM model checkpoint."""
    if _dl_cache["bilstm"] is not None:
        return _dl_cache["bilstm"], None
    if _dl_cache["bilstm_err"] is not None:
        return None, _dl_cache["bilstm_err"]

    pt_path = get_model_dir() / "bilstm_model.pt"
    if not pt_path.exists():
        return None, "Checkpoint bilstm_model.pt not found."

    try:
        model = CharBiLSTM()
        state = torch.load(pt_path, map_location="cpu")
        model.load_state_dict(state)
        model.eval()
        _dl_cache["bilstm"] = model
        return model, None
    except Exception as e:
        err = f"Failed to load BiLSTM model: {e}"
        _dl_cache["bilstm_err"] = err
        return None, err


def predict_cnn(url: str) -> Dict[str, Any]:
    """Inference for character-level CNN."""
    model, err = load_cnn()
    if model is None:
        return {"available": False, "probability": None, "message": "CNN NOT AVAILABLE", "detail": err}

    tokens = encode_url(url, max_len=DEFAULT_MAX_LEN)
    x = torch.tensor([tokens], dtype=torch.long)
    with torch.no_grad():
        prob = float(model.predict_proba(x)[0].item())

    return {
        "available": True,
        "probability": round(prob, 4),
        "model": "Character-CNN",
        "message": "CNN inference successful"
    }


def predict_bilstm(url: str) -> Dict[str, Any]:
    """Inference for character-level BiLSTM."""
    model, err = load_bilstm()
    if model is None:
        return {"available": False, "probability": None, "message": "BiLSTM NOT AVAILABLE", "detail": err}

    tokens = encode_url(url, max_len=DEFAULT_MAX_LEN)
    x = torch.tensor([tokens], dtype=torch.long)
    with torch.no_grad():
        prob = float(model.predict_proba(x)[0].item())

    return {
        "available": True,
        "probability": round(prob, 4),
        "model": "Character-BiLSTM",
        "message": "BiLSTM inference successful"
    }


def explain_dl(url: str) -> Dict[str, Any]:
    """Produce neural explainability attributions from CNN and BiLSTM."""
    cnn, _ = load_cnn()
    bilstm, _ = load_bilstm()

    out = {}
    if cnn is not None:
        out["cnn"] = explain_neural_prediction(cnn, url, model_name="Character-CNN")
    else:
        out["cnn"] = {"available": False, "reason": "Character-CNN model is not loaded."}

    if bilstm is not None:
        out["bilstm"] = explain_neural_prediction(bilstm, url, model_name="Character-BiLSTM")
    else:
        out["bilstm"] = {"available": False, "reason": "Character-BiLSTM model is not loaded."}

    return out


def status() -> Dict[str, Any]:
    """Report status of deep learning models."""
    cnn_m, cnn_e = load_cnn()
    lstm_m, lstm_e = load_bilstm()
    return {
        "cnn": {"available": cnn_m is not None, "message": "Loaded" if cnn_m else cnn_e},
        "bilstm": {"available": lstm_m is not None, "message": "Loaded" if lstm_m else lstm_e}
    }
