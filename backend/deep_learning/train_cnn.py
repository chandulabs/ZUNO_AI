"""Character-Level CNN Training Pipeline (PyTorch).

Usage:
  python -m deep_learning.train_cnn [--epochs 15] [--lr 0.001]
"""
import argparse
import time
from pathlib import Path
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.optim import Adam

from training.config import (
    MODEL_DIR,
    PROCESSED_DATA_DIR,
    RAW_DATA_DIR,
    CNN_PARAMS
)
from training.dataset_loader import process_dataset_pipeline
from training.evaluate import compute_comprehensive_metrics, save_model_metrics, generate_model_comparison
from training.model_registry import register_model
from .vocabulary import VOCAB_SIZE, DEFAULT_MAX_LEN
from .dataset import create_dataloader, URLCharDataset
from .cnn_model import CharCNN


def train_cnn(epochs: int = CNN_PARAMS["epochs"], lr: float = CNN_PARAMS["lr"]):
    print("=" * 60)
    print("PHISHGUARD AI — CHARACTER-LEVEL CNN TRAINING (PyTorch)")
    print("=" * 60)

    train_file = PROCESSED_DATA_DIR / "train.csv"
    val_file = PROCESSED_DATA_DIR / "val.csv"
    test_file = PROCESSED_DATA_DIR / "test.csv"

    if not (train_file.exists() and test_file.exists()):
        src_csv = RAW_DATA_DIR / "urls.csv"
        if not src_csv.exists():
            from training.build_dataset import create_initial_raw_dataset
            create_initial_raw_dataset()
        process_dataset_pipeline(src_csv)

    train_df = pd.read_csv(train_file)
    val_df = pd.read_csv(val_file)
    test_df = pd.read_csv(test_file)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Training on device: {device}")

    train_loader = create_dataloader(train_df["url"].tolist(), train_df["label"].tolist(), batch_size=CNN_PARAMS["batch_size"], shuffle=True)
    val_loader = create_dataloader(val_df["url"].tolist(), val_df["label"].tolist(), batch_size=CNN_PARAMS["batch_size"], shuffle=False)

    model = CharCNN(
        vocab_size=VOCAB_SIZE,
        embed_dim=CNN_PARAMS["embed_dim"],
        num_filters=CNN_PARAMS["num_filters"],
        dropout=CNN_PARAMS["dropout"]
    ).to(device)

    criterion = nn.BCEWithLogitsLoss()
    optimizer = Adam(model.parameters(), lr=lr, weight_decay=1e-5)

    best_val_loss = float("inf")
    patience = CNN_PARAMS["early_stopping_patience"]
    patience_counter = 0
    best_weights = None

    t0 = time.time()
    for epoch in range(1, epochs + 1):
        model.train()
        train_loss = 0.0
        for x_b, y_b in train_loader:
            x_b, y_b = x_b.to(device), y_b.to(device)
            optimizer.zero_grad()
            logits = model(x_b)
            loss = criterion(logits, y_b)
            loss.backward()
            optimizer.step()
            train_loss += loss.item() * len(y_b)
        train_loss /= len(train_df)

        model.eval()
        val_loss = 0.0
        with torch.no_grad():
            for x_v, y_v in val_loader:
                x_v, y_v = x_v.to(device), y_v.to(device)
                logits_v = model(x_v)
                loss_v = criterion(logits_v, y_v)
                val_loss += loss_v.item() * len(y_v)
        val_loss /= len(val_df)

        print(f"Epoch {epoch:02d}/{epochs:02d} | Train Loss: {train_loss:.4f} | Val Loss: {val_loss:.4f}")

        if val_loss < best_val_loss:
            best_val_loss = val_loss
            patience_counter = 0
            best_weights = {k: v.cpu().clone() for k, v in model.state_dict().items()}
        else:
            patience_counter += 1
            if patience_counter >= patience:
                print(f"Early stopping triggered at epoch {epoch}.")
                break

    print(f"Training completed in {time.time() - t0:.2f}s.")
    if best_weights:
        model.load_state_dict(best_weights)

    # Evaluation on held-out test set
    model.eval()
    test_loader = create_dataloader(test_df["url"].tolist(), test_df["label"].tolist(), batch_size=CNN_PARAMS["batch_size"], shuffle=False)
    test_probs = []
    t_start = time.time()
    with torch.no_grad():
        for x_t, _ in test_loader:
            x_t = x_t.to(device)
            p = torch.sigmoid(model(x_t))
            test_probs.extend(p.cpu().tolist())
    latency_ms = ((time.time() - t_start) / len(test_df)) * 1000

    metrics = compute_comprehensive_metrics(
        y_true=test_df["label"].tolist(),
        y_prob=test_probs,
        latency_ms=latency_ms,
        model_name="Character-CNN",
        threshold=0.50
    )

    print("\n--- CNN Test Evaluation Metrics ---")
    print(f"Accuracy:  {metrics['accuracy'] * 100:.2f}%")
    print(f"Precision: {metrics['precision'] * 100:.2f}%")
    print(f"Recall:    {metrics['recall'] * 100:.2f}%")
    print(f"F1 Score:  {metrics['f1_score']:.4f}")
    print(f"ROC-AUC:   {metrics['roc_auc']:.4f}")
    print(f"Latency:   {metrics['latency_ms']:.2f} ms/URL")

    # Save artifact
    cnn_file = MODEL_DIR / "cnn_model.pt"
    torch.save(model.state_dict(), cnn_file)
    print(f"Saved CNN model checkpoint to {cnn_file}")

    save_model_metrics("cnn", metrics)
    register_model(
        name="cnn",
        file_path=cnn_file,
        version="2.0.0",
        framework="pytorch",
        metrics=metrics,
        approved=True
    )
    generate_model_comparison()
    return metrics


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--epochs", type=int, default=CNN_PARAMS["epochs"])
    parser.add_argument("--lr", type=float, default=CNN_PARAMS["lr"])
    args = parser.parse_args()
    train_cnn(epochs=args.epochs, lr=args.lr)
