from __future__ import annotations
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, precision_score, recall_score
from sklearn.model_selection import GroupShuffleSplit, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.app.services.feature_extraction import FEATURE_NAMES, extract_features
from backend.app.services.url_validator import URLValidationError, normalize_url
from training.data_loader import load_dataset
from training.preprocessing import normalize_labels
from training.evaluate import choose_threshold, classification_metrics, write_evaluation

def host_group(url: str) -> str:
    from urllib.parse import urlsplit
    try:
        return (urlsplit(url.strip() if "://" in url else "//" + url.strip()).hostname or "").casefold()
    except ValueError:
        return ""

def split_data(frame: pd.DataFrame, labels: pd.Series, groups: pd.Series, random_state: int):
    indices = np.arange(len(frame))
    if groups.nunique() >= 10:
        best, best_score = None, float("inf")
        for seed in range(random_state, random_state + 50):
            outer = GroupShuffleSplit(n_splits=1, test_size=0.15, random_state=seed)
            train_val, test = next(outer.split(indices, labels, groups))
            inner = GroupShuffleSplit(n_splits=1, test_size=0.15 / 0.85, random_state=seed + 997)
            train_rel, val_rel = next(inner.split(train_val, labels.iloc[train_val], groups.iloc[train_val]))
            train, validation = train_val[train_rel], train_val[val_rel]
            sizes = np.array([len(train), len(validation), len(test)]) / len(frame)
            class_rates = [labels.iloc[part].mean() for part in (train, validation, test)]
            score = float(np.abs(sizes - [0.70, 0.15, 0.15]).sum() + np.std(class_rates))
            if score < best_score and all(labels.iloc[part].nunique() == 2 for part in (train, validation, test)):
                best, best_score = (train, validation, test), score
        if best is not None:
            return best, "host_grouped"
    train_val, test = train_test_split(indices, test_size=0.15, random_state=random_state, stratify=labels)
    train, validation = train_test_split(train_val, test_size=0.15 / 0.85, random_state=random_state, stratify=labels.iloc[train_val])
    return (train, validation, test), "stratified_row_fallback"

def positive_scores(model, matrix) -> np.ndarray:
    return model.predict_proba(matrix)[:, list(model.classes_).index(1)]

def main() -> None:
    parser = argparse.ArgumentParser(description="Train PhishGuard using a labeled raw-URL CSV.")
    parser.add_argument("--dataset", required=True, help="Path to the CSV dataset")
    parser.add_argument("--url-column", default="URL")
    parser.add_argument("--label-column", default="label")
    parser.add_argument("--phishing-label", default="0", help="Raw value that means phishing")
    parser.add_argument("--legitimate-label", default="1", help="Raw value that means legitimate")
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "artifacts")
    args = parser.parse_args()

    raw, dataset_report = load_dataset(args.dataset, args.url_column, args.label_column)
    raw["label"] = normalize_labels(raw["raw_label"], args.phishing_label, args.legitimate_label)
    normalized_urls = []
    invalid_urls = 0
    for url in raw["url"]:
        try:
            normalized_urls.append(normalize_url(url))
        except URLValidationError:
            normalized_urls.append(None)
            invalid_urls += 1
    raw["url"] = normalized_urls
    dataset_report["invalid_urls_removed_by_validation"] = invalid_urls
    raw = raw.dropna(subset=["url"]).reset_index(drop=True)
    before_normalized_deduplication = len(raw)
    raw = raw.drop_duplicates(subset=["url"], keep="first").reset_index(drop=True)
    dataset_report["duplicate_normalized_urls_removed"] = before_normalized_deduplication - len(raw)
    raw["host"] = raw["url"].map(host_group)
    raw = raw[raw["host"].ne("")].reset_index(drop=True)
    matrix_frame = pd.DataFrame([extract_features(url) for url in raw["url"]], columns=FEATURE_NAMES)
    labels, groups = raw["label"], raw["host"]
    (train_idx, validation_idx, test_idx), split_strategy = split_data(raw, labels, groups, args.random_state)
    X_train, y_train = matrix_frame.iloc[train_idx], labels.iloc[train_idx]
    X_val, y_val = matrix_frame.iloc[validation_idx], labels.iloc[validation_idx]
    X_test, y_test = matrix_frame.iloc[test_idx], labels.iloc[test_idx]

    models = {
        "Logistic Regression": Pipeline([("scaler", StandardScaler()), ("classifier", LogisticRegression(class_weight="balanced", max_iter=2000, random_state=args.random_state))]),
        "Random Forest": RandomForestClassifier(n_estimators=300, max_depth=24, min_samples_leaf=2, class_weight="balanced", n_jobs=-1, random_state=args.random_state),
    }
    fitted, validation_results = {}, {}
    for name, model in models.items():
        model.fit(X_train, y_train)
        scores = positive_scores(model, X_val)
        predictions = scores >= 0.5
        validation_results[name] = {"precision": float(precision_score(y_val, predictions, zero_division=0)), "recall": float(recall_score(y_val, predictions, zero_division=0)), "f1_score": float(f1_score(y_val, predictions, zero_division=0))}
        fitted[name] = model
    selected_name = max(validation_results, key=lambda name: (validation_results[name]["f1_score"], validation_results[name]["recall"], validation_results[name]["precision"]))
    selected = fitted[selected_name]
    threshold = choose_threshold(y_val, positive_scores(selected, X_val))
    test_metrics = classification_metrics(y_test, positive_scores(selected, X_test), threshold)
    dataset_report.update({"label_mapping": {"phishing": args.phishing_label, "legitimate": args.legitimate_label}, "class_distribution_cleaned": {"legitimate": int((labels == 0).sum()), "phishing": int((labels == 1).sum())}})
    report = {"created_at_utc": datetime.now(timezone.utc).isoformat(), "dataset": dataset_report, "split": {"strategy": split_strategy, "random_state": args.random_state, "train_rows": len(train_idx), "validation_rows": len(validation_idx), "test_rows": len(test_idx), "train_class_distribution": {"legitimate": int((y_train == 0).sum()), "phishing": int((y_train == 1).sum())}, "validation_class_distribution": {"legitimate": int((y_val == 0).sum()), "phishing": int((y_val == 1).sum())}, "test_class_distribution": {"legitimate": int((y_test == 0).sum()), "phishing": int((y_test == 1).sum())}}, "algorithms_compared": list(models), "validation_comparison": validation_results, "selected_algorithm": selected_name, "threshold": threshold, "test_metrics": test_metrics, "feature_names": FEATURE_NAMES, "sklearn_version": sklearn.__version__}
    model_dir = args.output_dir / "model"
    model_dir.mkdir(parents=True, exist_ok=True)
    bundle = {"model": selected, "feature_names": FEATURE_NAMES, "threshold": threshold, "algorithm": selected_name, "metadata": {"trained_at_utc": report["created_at_utc"], "dataset": dataset_report, "sklearn_version": sklearn.__version__, "random_state": args.random_state}}
    joblib.dump(bundle, model_dir / "phishguard_model.joblib")
    write_evaluation(args.output_dir / "evaluation", report)
    print(json.dumps({"selected_algorithm": selected_name, "threshold": threshold, "test_metrics": test_metrics, "artifacts": str(args.output_dir)}, indent=2))

if __name__ == "__main__":
    main()

