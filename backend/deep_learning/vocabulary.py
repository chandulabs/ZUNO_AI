"""Character Vocabulary and Tokenizer for Character-level Deep Learning Models.

Consistent mapping of raw URL characters to token IDs.
"""
import string
from typing import List, Dict

# Character vocabulary: PAD=0, UNK=1, followed by standard printable ASCII
PAD_TOKEN = "<PAD>"
UNK_TOKEN = "<UNK>"
PAD_IDX = 0
UNK_IDX = 1

# Standard printable ASCII (digits, ascii_letters, punctuation)
CHARACTERS = [PAD_TOKEN, UNK_TOKEN] + list(string.digits + string.ascii_lowercase + string.ascii_uppercase + string.punctuation)

CHAR2IDX: Dict[str, int] = {c: i for i, c in enumerate(CHARACTERS)}
IDX2CHAR: Dict[int, str] = {i: c for i, c in enumerate(CHARACTERS)}
VOCAB_SIZE: int = len(CHARACTERS)
DEFAULT_MAX_LEN: int = 200


def encode_url(url: str, max_len: int = DEFAULT_MAX_LEN) -> List[int]:
    """Encode a URL into fixed-length integer character IDs with padding/truncation."""
    indices = [CHAR2IDX.get(c, UNK_IDX) for c in url[:max_len]]
    if len(indices) < max_len:
        indices += [PAD_IDX] * (max_len - len(indices))
    return indices


def decode_indices(indices: List[int]) -> str:
    """Decode integer character IDs back to a readable string."""
    chars = []
    for idx in indices:
        if idx == PAD_IDX:
            break
        chars.append(IDX2CHAR.get(idx, "?"))
    return "".join(chars)
