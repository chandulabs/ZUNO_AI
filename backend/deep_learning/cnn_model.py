"""Character-level Convolutional Neural Network (CNN) for URL Phishing Detection.

Architecture:
  Chars -> Embedding -> Conv1D(128, k=3) -> ReLU -> MaxPool
        -> Conv1D(128, k=5) -> ReLU -> MaxPool
        -> Conv1D(256, k=7) -> ReLU -> AdaptiveMaxPool1d(1)
        -> Linear(256, 128) -> ReLU -> Dropout -> Linear(128, 1) -> Sigmoid
"""
import torch
import torch.nn as nn
from .vocabulary import VOCAB_SIZE, PAD_IDX


class CharCNN(nn.Module):
    def __init__(self, vocab_size: int = VOCAB_SIZE, embed_dim: int = 64, num_filters: int = 128, dropout: float = 0.3):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=PAD_IDX)
        
        # 1D Convolutions expect input shape (batch, channels, seq_len)
        self.conv1 = nn.Conv1d(embed_dim, num_filters, kernel_size=3, padding=1)
        self.conv2 = nn.Conv1d(num_filters, num_filters, kernel_size=5, padding=2)
        self.conv3 = nn.Conv1d(num_filters, num_filters * 2, kernel_size=7, padding=3)

        self.relu = nn.ReLU()
        self.pool = nn.MaxPool1d(kernel_size=2)
        self.global_pool = nn.AdaptiveMaxPool1d(1)

        self.fc1 = nn.Linear(num_filters * 2, 128)
        self.dropout = nn.Dropout(dropout)
        self.fc2 = nn.Linear(128, 1)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: (batch_size, seq_len)
        emb = self.embedding(x)  # (batch_size, seq_len, embed_dim)
        emb = emb.transpose(1, 2)  # (batch_size, embed_dim, seq_len)

        c1 = self.pool(self.relu(self.conv1(emb)))
        c2 = self.pool(self.relu(self.conv2(c1)))
        c3 = self.relu(self.conv3(c2))

        pooled = self.global_pool(c3).squeeze(2)  # (batch_size, num_filters * 2)
        h = self.dropout(self.relu(self.fc1(pooled)))
        logits = self.fc2(h).squeeze(-1)  # (batch_size,)
        return logits

    def predict_proba(self, x: torch.Tensor) -> torch.Tensor:
        """Returns probability of being phishing (0.0 to 1.0)."""
        logits = self.forward(x)
        return torch.sigmoid(logits)
