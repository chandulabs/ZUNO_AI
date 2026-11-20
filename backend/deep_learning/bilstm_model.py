"""Character-level Bidirectional LSTM (BiLSTM) for URL Phishing Detection.

Architecture:
  Chars -> Embedding(embed_dim=64)
        -> BiLSTM(hidden_dim=64, num_layers=2, bidirectional=True)
        -> Dropout(0.3)
        -> Linear(128, 64) -> ReLU
        -> Linear(64, 1) -> Sigmoid
"""
import torch
import torch.nn as nn
from .vocabulary import VOCAB_SIZE, PAD_IDX


class CharBiLSTM(nn.Module):
    def __init__(self, vocab_size: int = VOCAB_SIZE, embed_dim: int = 64, hidden_dim: int = 64, num_layers: int = 2, dropout: float = 0.3):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=PAD_IDX)
        self.lstm = nn.LSTM(
            input_size=embed_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            bidirectional=True,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0.0
        )
        self.dropout = nn.Dropout(dropout)
        self.fc1 = nn.Linear(hidden_dim * 2, 64)
        self.relu = nn.ReLU()
        self.fc2 = nn.Linear(64, 1)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: (batch_size, seq_len)
        emb = self.embedding(x)  # (batch_size, seq_len, embed_dim)
        out, (h_n, c_n) = self.lstm(emb)  # out: (batch_size, seq_len, hidden_dim * 2)

        # Max-pool across time steps to capture most salient sequence features
        pooled, _ = torch.max(out, dim=1)  # (batch_size, hidden_dim * 2)
        h = self.dropout(pooled)
        h = self.relu(self.fc1(h))
        logits = self.fc2(h).squeeze(-1)  # (batch_size,)
        return logits

    def predict_proba(self, x: torch.Tensor) -> torch.Tensor:
        """Returns probability of being phishing (0.0 to 1.0)."""
        logits = self.forward(x)
        return torch.sigmoid(logits)
