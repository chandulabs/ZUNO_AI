"""Character-level Neural Network Explainability.

Uses character-level occlusion attribution on the actual PyTorch CNN and BiLSTM
models to compute real token-level importance and identify influential sequences.
Outputs are derived entirely from real model predictions without estimation.
"""
import torch
from typing import Dict, Any, List
from .vocabulary import encode_url, PAD_IDX, UNK_IDX, DEFAULT_MAX_LEN


def explain_neural_prediction(model: torch.nn.Module, url: str, model_name: str = "CNN", max_len: int = DEFAULT_MAX_LEN) -> Dict[str, Any]:
    """Compute real character-level attribution using occlusion against the neural model."""
    model.eval()
    u_chars = list(url[:max_len])
    tokens = encode_url(url, max_len=max_len)
    x = torch.tensor([tokens], dtype=torch.long)

    with torch.no_grad():
        base_prob = float(model.predict_proba(x)[0].item())

    # If the URL is very short or baseline is computed, evaluate occlusion for each character
    attributions: List[float] = []
    
    # Batch occlusion evaluation for speed and efficiency
    # Create batch where each row has character i replaced by PAD_IDX
    n = len(u_chars)
    if n == 0:
        return {
            "available": True,
            "model_name": model_name,
            "base_probability": base_prob,
            "tokens": [],
            "top_positive_sequences": [],
            "top_negative_sequences": [],
            "summary": "Empty URL input."
        }

    batch_tokens = []
    for i in range(n):
        occluded = list(tokens)
        occluded[i] = PAD_IDX  # mask character
        batch_tokens.append(occluded)

    batch_x = torch.tensor(batch_tokens, dtype=torch.long)
    with torch.no_grad():
        occluded_probs = model.predict_proba(batch_x).tolist()

    # Attribution = base_prob - occluded_prob
    # Positive: character pushed score TOWARD phishing
    # Negative: character pushed score TOWARD benign
    token_attributions = []
    for i, ch in enumerate(u_chars):
        attr = round(base_prob - float(occluded_probs[i]), 5)
        attributions.append(attr)
        token_attributions.append({
            "char": ch,
            "index": i,
            "attribution": attr
        })

    # Group into multi-character influential tokens / n-grams
    # Find contiguous spans with high positive or negative attribution
    spans = []
    curr_span = ""
    curr_attr = 0.0
    for item in token_attributions:
        if abs(item["attribution"]) > 0.001:
            curr_span += item["char"]
            curr_attr += item["attribution"]
        else:
            if len(curr_span) >= 2:
                spans.append({"sequence": curr_span, "attribution": round(curr_attr, 4)})
            curr_span = ""
            curr_attr = 0.0
    if len(curr_span) >= 2:
        spans.append({"sequence": curr_span, "attribution": round(curr_attr, 4)})

    top_pos = sorted([s for s in spans if s["attribution"] > 0], key=lambda x: -x["attribution"])[:5]
    top_neg = sorted([s for s in spans if s["attribution"] < 0], key=lambda x: x["attribution"])[:5]

    summary = (
        f"{model_name} character attribution identified "
        f"{len(top_pos)} suspicious sequence(s) increasing risk "
        f"and {len(top_neg)} sequence(s) lowering risk."
    )

    return {
        "available": True,
        "model_name": model_name,
        "base_probability": round(base_prob, 4),
        "tokens": token_attributions[:120],  # cap for clean UI rendering
        "top_positive_sequences": top_pos,
        "top_negative_sequences": top_neg,
        "summary": summary
    }
