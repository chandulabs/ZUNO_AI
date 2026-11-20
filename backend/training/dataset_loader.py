"""Dataset Engineering and Preprocessing Pipeline.

Handles ingestion, normalization, filtering, domain-grouped splitting to prevent
data leakage, and generating train/val/test splits with detailed provenance.
"""
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Tuple
import pandas as pd
from urllib.parse import urlparse

from .config import (
    RAW_DATA_DIR,
    PROCESSED_DATA_DIR,
    REPORTS_DATA_DIR,
    RANDOM_STATE,
    TEST_SPLIT,
    VAL_SPLIT
)
from detection.features import normalize, extract, NAMES


def get_registrable_domain(url: str) -> str:
    """Extract registrable domain grouping key to prevent data leakage across splits."""
    try:
        p = urlparse(url if "://" in url else f"http://{url}")
        host = (p.hostname or "").lower().rstrip(".")
        if not host:
            return "unknown"
        # If IP address, use IP as domain group
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
            return host
        parts = host.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return host
    except Exception:
        return "unknown"


def clean_and_normalize_dataset(df: pd.DataFrame, source_name: str = "raw") -> pd.DataFrame:
    """Normalize, filter, and validate raw URL data."""
    if not {"url", "label"}.issubset(df.columns):
        raise ValueError("Dataset must contain 'url' and 'label' columns.")

    if "source" not in df.columns:
        df["source"] = source_name

    initial_count = len(df)
    # Filter nulls
    df = df.dropna(subset=["url", "label"]).copy()
    df["label"] = df["label"].astype(int)
    # Ensure binary labels 0 and 1
    df = df[df["label"].isin([0, 1])].copy()

    valid_records = []
    skipped_invalid = 0

    for _, row in df.iterrows():
        raw_u = str(row["url"]).strip()
        try:
            norm_u = normalize(raw_u)
            reg_dom = get_registrable_domain(norm_u)
            valid_records.append({
                "url": norm_u,
                "label": int(row["label"]),
                "source": str(row["source"]),
                "domain_group": reg_dom
            })
        except ValueError:
            skipped_invalid += 1

    clean_df = pd.DataFrame(valid_records)
    # Remove exact duplicate URLs
    clean_df = clean_df.drop_duplicates(subset=["url"]).reset_index(drop=True)
    return clean_df


def split_by_domain_group(df: pd.DataFrame, test_size: float = TEST_SPLIT, val_size: float = VAL_SPLIT, random_state: int = RANDOM_STATE) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Group-split dataset by domain to prevent data leakage between train/val/test splits."""
    domains = list(df["domain_group"].unique())
    import numpy as np
    rng = np.random.RandomState(random_state)
    rng.shuffle(domains)

    n_total = len(domains)
    n_test = max(1, int(n_total * test_size))
    n_val = max(1, int(n_total * val_size))

    test_doms = set(domains[:n_test])
    val_doms = set(domains[n_test:n_test + n_val])
    train_doms = set(domains[n_test + n_val:])

    train_df = df[df["domain_group"].isin(train_doms)].copy()
    val_df = df[df["domain_group"].isin(val_doms)].copy()
    test_df = df[df["domain_group"].isin(test_doms)].copy()

    # Safety check: if class is missing in val or test due to grouping, stratify by individual rows as fallback
    if train_df["label"].nunique() < 2 or val_df["label"].nunique() < 2 or test_df["label"].nunique() < 2:
        from sklearn.model_selection import train_test_split
        train_val, test_df = train_test_split(df, test_size=test_size, stratify=df["label"], random_state=random_state)
        val_rel_size = val_size / (1.0 - test_size)
        train_df, val_df = train_test_split(train_val, test_size=val_rel_size, stratify=train_val["label"], random_state=random_state)

    return train_df.reset_index(drop=True), val_df.reset_index(drop=True), test_df.reset_index(drop=True)


def process_dataset_pipeline(input_csv_or_df, dataset_version: str = "v1.0") -> Dict[str, Any]:
    """Run full dataset preparation pipeline and save processed splits with metadata."""
    if isinstance(input_csv_or_df, (str, Path)):
        raw_df = pd.read_csv(input_csv_or_df)
    else:
        raw_df = input_csv_or_df

    clean_df = clean_and_normalize_dataset(raw_df)
    train_df, val_df, test_df = split_by_domain_group(clean_df)

    # Save processed CSVs
    train_path = PROCESSED_DATA_DIR / "train.csv"
    val_path = PROCESSED_DATA_DIR / "val.csv"
    test_path = PROCESSED_DATA_DIR / "test.csv"

    train_df.to_csv(train_path, index=False)
    val_df.to_csv(val_path, index=False)
    test_df.to_csv(test_path, index=False)

    report = {
        "dataset_version": dataset_version,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "total_valid_urls": len(clean_df),
        "class_distribution": {
            "total_benign": int((clean_df["label"] == 0).sum()),
            "total_phishing": int((clean_df["label"] == 1).sum()),
            "phishing_ratio": round(float((clean_df["label"] == 1).mean()), 4)
        },
        "splits": {
            "train": {
                "count": len(train_df),
                "benign": int((train_df["label"] == 0).sum()),
                "phishing": int((train_df["label"] == 1).sum()),
                "path": str(train_path)
            },
            "val": {
                "count": len(val_df),
                "benign": int((val_df["label"] == 0).sum()),
                "phishing": int((val_df["label"] == 1).sum()),
                "path": str(val_path)
            },
            "test": {
                "count": len(test_df),
                "benign": int((test_df["label"] == 0).sum()),
                "phishing": int((test_df["label"] == 1).sum()),
                "path": str(test_path)
            }
        },
        "sources": {str(k): int(v) for k, v in clean_df["source"].value_counts().items()}
    }

    report_path = REPORTS_DATA_DIR / f"dataset_report_{dataset_version}.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    return report
