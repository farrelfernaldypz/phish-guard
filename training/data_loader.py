from __future__ import annotations
from pathlib import Path
import pandas as pd

def load_dataset(path: str | Path, url_column: str, label_column: str) -> tuple[pd.DataFrame, dict]:
    dataset_path = Path(path)
    if not dataset_path.is_file():
        raise FileNotFoundError(f"Dataset file was not found: {dataset_path}")
    frame = pd.read_csv(dataset_path, low_memory=False)
    missing_columns = [name for name in (url_column, label_column) if name not in frame.columns]
    if missing_columns:
        raise ValueError(f"Missing required dataset column(s): {', '.join(missing_columns)}. Available columns: {', '.join(map(str, frame.columns))}")
    report = {"source_file": dataset_path.name, "source_rows": int(len(frame)), "columns": list(map(str, frame.columns)), "missing_urls": int(frame[url_column].isna().sum()), "missing_labels": int(frame[label_column].isna().sum()), "duplicate_urls_before_cleaning": int(frame[url_column].duplicated().sum()), "class_distribution_raw": {str(key): int(value) for key, value in frame[label_column].value_counts(dropna=False).items()}}
    cleaned = frame[[url_column, label_column]].dropna().copy()
    report["rows_removed_missing_url_or_label"] = int(len(frame) - len(cleaned))
    cleaned[url_column] = cleaned[url_column].astype(str).str.strip()
    cleaned = cleaned[cleaned[url_column].ne("")]
    report["empty_urls_removed"] = int(report["source_rows"] - report["rows_removed_missing_url_or_label"] - len(cleaned))
    duplicate_count = int(cleaned[url_column].duplicated().sum())
    cleaned = cleaned.drop_duplicates(subset=[url_column], keep="first").reset_index(drop=True)
    report["rows_after_cleaning"] = int(len(cleaned))
    report["duplicate_urls_removed"] = duplicate_count
    return cleaned.rename(columns={url_column: "url", label_column: "raw_label"}), report

