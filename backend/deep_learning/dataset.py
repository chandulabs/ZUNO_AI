"""PyTorch Dataset for Character-level URL Modeling."""
import torch
from torch.utils.data import Dataset, DataLoader
from typing import List, Tuple
from .vocabulary import encode_url, DEFAULT_MAX_LEN


class URLCharDataset(Dataset):
    """Dataset mapping raw URL strings to tokenized character tensors and labels."""
    def __init__(self, urls: List[str], labels: List[int], max_len: int = DEFAULT_MAX_LEN):
        self.urls = list(urls)
        self.labels = list(labels)
        self.max_len = max_len

    def __len__(self) -> int:
        return len(self.urls)

    def __getitem__(self, idx: int) -> Tuple[torch.Tensor, torch.Tensor]:
        u = str(self.urls[idx])
        y = float(self.labels[idx])
        tokens = encode_url(u, max_len=self.max_len)
        return torch.tensor(tokens, dtype=torch.long), torch.tensor(y, dtype=torch.float32)


def create_dataloader(urls: List[str], labels: List[int], batch_size: int = 64, shuffle: bool = True, max_len: int = DEFAULT_MAX_LEN) -> DataLoader:
    ds = URLCharDataset(urls, labels, max_len=max_len)
    return DataLoader(ds, batch_size=batch_size, shuffle=shuffle, drop_last=False)
