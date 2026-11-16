from __future__ import annotations
from pathlib import Path
from typing import Any
import joblib
import numpy as np
from ..core.config import MODEL_PATH
from .feature_extraction import FEATURE_NAMES, extract_features

class ModelNotReadyError(RuntimeError):
    pass

class PredictionService:
    def __init__(self, model_path: Path = MODEL_PATH) -> None:
        self.model_path = model_path
        self.bundle: dict[str, Any] | None = None
        self.load_error: str | None = None
        self.reload()

    def reload(self) -> None:
        self.bundle, self.load_error = None, None
        target_path = self.model_path
        if not target_path.is_file():
            candidates = [
                target_path,
                target_path.parent / "phishguard_model.joblib",
                target_path.parent / "model_phishing.pkl",
                target_path.parent / "model_phishing.joblib",
            ]
            found = next((p for p in candidates if p.is_file()), None)
            if not found:
                self.load_error = "Trained model artifact is not available."
                return
            target_path = found

        try:
            loaded = joblib.load(target_path)
            if isinstance(loaded, dict) and {"model", "feature_names"}.issubset(loaded):
                threshold = float(loaded.get("threshold", 0.5))
                algorithm = loaded.get("algorithm", type(loaded["model"]).__name__)
                self.bundle = {
                    "model": loaded["model"],
                    "feature_names": list(loaded["feature_names"]),
                    "threshold": threshold,
                    "algorithm": algorithm,
                    "metadata": loaded.get("metadata", {}),
                }
            elif hasattr(loaded, "predict_proba"):
                feature_names = getattr(loaded, "feature_names_in_", None)
                if feature_names is not None:
                    feature_names = list(feature_names)
                else:
                    feature_names = [
                        "url_length", "hostname_length", "count_dot", "count_hyphen",
                        "count_at", "count_question", "count_equal", "count_slash",
                        "has_https", "has_ip", "suspicious_words"
                    ]
                self.bundle = {
                    "model": loaded,
                    "feature_names": feature_names,
                    "threshold": 0.5,
                    "algorithm": type(loaded).__name__,
                    "metadata": {"type": "raw_classifier", "source_file": target_path.name},
                }
            else:
                raise ValueError("Invalid model bundle format.")
        except Exception as error:
            self.load_error = f"Model artifact could not be loaded: {type(error).__name__}."

    @property
    def ready(self) -> bool:
        return self.bundle is not None

    def model_info(self) -> dict[str, Any]:
        if not self.bundle:
            return {"status": "not_ready", "model_name": None, "feature_names": FEATURE_NAMES, "metadata": None, "message": self.load_error}
        return {"status": "ready", "model_name": self.bundle.get("algorithm"), "feature_names": self.bundle["feature_names"], "threshold": float(self.bundle["threshold"]), "metadata": self.bundle.get("metadata", {}), "message": None}

    def predict(self, url: str) -> dict[str, Any]:
        if not self.bundle:
            raise RuntimeError(self.load_error or "Model is unavailable.")
        feature_map = extract_features(url, self.bundle["feature_names"])
        import pandas as pd
        vector = pd.DataFrame([[feature_map[name] for name in self.bundle["feature_names"]]], columns=self.bundle["feature_names"])
        model = self.bundle["model"]
        positive_index = list(model.classes_).index(1)
        score = float(model.predict_proba(vector)[0][positive_index])
        threshold = float(self.bundle["threshold"])
        is_phishing = score >= threshold
        indicator_keys = (
            "has_ip_address", "has_ip", "has_punycode", "has_port",
            "has_suspicious_keyword", "suspicious_keyword_count", "suspicious_words",
            "has_url_shortener", "has_double_slash_redirect_pattern",
            "uses_https", "has_https", "count_subdomains", "url_length"
        )
        relevant = [name for name in indicator_keys if feature_map.get(name)]
        return {"prediction": int(is_phishing), "label": "Phishing" if is_phishing else "Legitimate", "model_score": score, "threshold": threshold, "features": feature_map, "relevant_indicators": relevant, "model_name": self.bundle.get("algorithm")}

