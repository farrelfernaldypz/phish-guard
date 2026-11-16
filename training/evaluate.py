from __future__ import annotations
import json
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from sklearn.metrics import accuracy_score, average_precision_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score

def classification_metrics(y_true, scores, threshold: float) -> dict:
    predictions = (np.asarray(scores) >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, predictions, labels=[0, 1]).ravel()
    result = {"accuracy": float(accuracy_score(y_true, predictions)), "precision": float(precision_score(y_true, predictions, zero_division=0)), "recall": float(recall_score(y_true, predictions, zero_division=0)), "f1_score": float(f1_score(y_true, predictions, zero_division=0)), "false_positive": int(fp), "false_negative": int(fn), "true_positive": int(tp), "true_negative": int(tn), "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]], "threshold": float(threshold)}
    try:
        result["roc_auc"] = float(roc_auc_score(y_true, scores))
        result["pr_auc"] = float(average_precision_score(y_true, scores))
    except ValueError:
        result["roc_auc"], result["pr_auc"] = None, None
    return result

def choose_threshold(y_true, scores) -> float:
    score_values = np.asarray(scores)
    candidates = np.unique(np.concatenate([np.linspace(0.01, 0.99, 99), np.quantile(score_values, np.linspace(0, 1, 101))]))
    best_threshold, best_key = 0.5, (-1.0, -1.0, -1.0)
    for threshold in candidates:
        result = classification_metrics(y_true, scores, float(threshold))
        precision, recall = result["precision"], result["recall"]
        f2 = 5 * precision * recall / (4 * precision + recall) if precision + recall else 0.0
        if (f2, recall, precision) > best_key:
            best_key, best_threshold = (f2, recall, precision), float(threshold)
    return best_threshold

def write_evaluation(output_dir: Path, report: dict) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "metrics.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    comparison, metrics = report["validation_comparison"], report["test_metrics"]
    lines = ["# PhishGuard Evaluation", "", "Results below are generated only after training and test evaluation on the supplied dataset.", "", f"- Dataset: {report['dataset']['source_file']}", f"- Split sizes: train {report['split']['train_rows']}, validation {report['split']['validation_rows']}, test {report['split']['test_rows']}", f"- Split strategy: {report['split']['strategy']}", f"- Selected model: {report['selected_algorithm']}", f"- Decision threshold selected using validation only: {report['threshold']:.4f}", "", "## Validation comparison", "", "| Algorithm | Precision | Recall | F1 |", "|---|---:|---:|---:|"]
    for name, values in comparison.items():
        lines.append(f"| {name} | {values['precision']:.4f} | {values['recall']:.4f} | {values['f1_score']:.4f} |")
    lines += ["", "## Held-out test metrics", ""]
    for key in ("accuracy", "precision", "recall", "f1_score", "roc_auc", "pr_auc", "false_positive", "false_negative"):
        lines.append(f"- {key}: {metrics.get(key)}")
    lines += ["", f"Confusion matrix (true rows legitimate, phishing; predicted columns legitimate, phishing): {metrics['confusion_matrix']}", "", "## Error analysis", "", f"- False positives: {metrics['false_positive']} legitimate test URLs classified as phishing. Review the corresponding dataset rows before operational use.", f"- False negatives: {metrics['false_negative']} phishing test URLs classified as legitimate. These are safety-relevant and warrant review.", "", "## Limitations", "", "- Results describe this supplied static dataset and split; they do not establish performance on future campaigns or unseen populations.", "- Host grouping reduces same-host leakage when enough distinct hosts exist; fallback row stratification can overstate generalization.", "- This model uses URL-string features only. It does not visit websites and cannot assess page content, reputation, redirects, or current threat intelligence.", "- Model score is not a calibrated probability. The threshold is selected on validation data.", ""]
    (output_dir / "evaluation.md").write_text("\n".join(lines), encoding="utf-8")
    _write_plots(output_dir, comparison, metrics)

def _write_plots(output_dir: Path, comparison: dict, metrics: dict) -> None:
    matrix = np.asarray(metrics["confusion_matrix"])
    fig, axis = plt.subplots(figsize=(5, 4))
    image = axis.imshow(matrix, cmap="Blues")
    axis.set(xticks=[0, 1], yticks=[0, 1], xticklabels=["Legitimate", "Phishing"], yticklabels=["Legitimate", "Phishing"], xlabel="Predicted", ylabel="Actual", title="Test Confusion Matrix")
    for (row, col), value in np.ndenumerate(matrix):
        axis.text(col, row, str(value), ha="center", va="center")
    fig.colorbar(image, ax=axis); fig.tight_layout(); fig.savefig(output_dir / "confusion_matrix.png", dpi=150); plt.close(fig)
    names = list(comparison)
    fig, axis = plt.subplots(figsize=(7, 4))
    width = 0.24
    for index, metric in enumerate(("precision", "recall", "f1_score")):
        axis.bar(np.arange(len(names)) + (index - 1) * width, [comparison[name][metric] for name in names], width, label=metric.replace("_", " ").title())
    axis.set_xticks(np.arange(len(names)), names); axis.set_ylim(0, 1); axis.set_title("Validation Model Comparison"); axis.legend(); fig.tight_layout(); fig.savefig(output_dir / "model_comparison.png", dpi=150); plt.close(fig)
    keys = ["accuracy", "precision", "recall", "f1_score"]
    fig, axis = plt.subplots(figsize=(7, 4))
    axis.bar([key.replace("_", " ").title() for key in keys], [metrics[key] for key in keys], color="#28b6b1")
    axis.set_ylim(0, 1); axis.set_title("Held-out Test Classification Metrics"); fig.tight_layout(); fig.savefig(output_dir / "classification_metrics.png", dpi=150); plt.close(fig)

