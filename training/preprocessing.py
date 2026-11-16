from __future__ import annotations
import math
import pandas as pd

def _canonical_label(value: object) -> str:
    normalized = str(value).strip().casefold()
    try:
        number = float(normalized)
        if math.isfinite(number) and number.is_integer():
            return str(int(number))
    except ValueError:
        pass
    return normalized

def normalize_labels(labels: pd.Series, phishing_label: str, legitimate_label: str) -> pd.Series:
    phishing, legitimate = _canonical_label(phishing_label), _canonical_label(legitimate_label)
    if phishing == legitimate:
        raise ValueError("Phishing and legitimate label mappings must differ.")
    values = labels.map(_canonical_label)
    unknown = sorted(set(values) - {phishing, legitimate})
    if unknown:
        raise ValueError(f"Unmapped labels found: {', '.join(unknown[:10])}")
    return values.map({legitimate: 0, phishing: 1}).astype("int8")

