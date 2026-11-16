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
        if not self.model_path.is_file():
            self.load_error = "Trained model artifact is not available."
            return
        try:
            loaded = joblib.load(self.model_path)
            if not isinstance(loaded, dict) or not {"model", "feature_names", "threshold"}.issubset(loaded):
                raise ValueError("Invalid model bundle format.")
            if loaded["feature_names"] != FEATURE_NAMES:
                raise ValueError("Model feature schema does not match this application version.")
            self.bundle = loaded
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
        feature_map = extract_features(url)
        vector = np.asarray([[feature_map[name] for name in self.bundle["feature_names"]]], dtype=float)
        model = self.bundle["model"]
        positive_index = list(model.classes_).index(1)
        score = float(model.predict_proba(vector)[0][positive_index])
        threshold = float(self.bundle["threshold"])
        is_phishing = score >= threshold
        relevant = [name for name in ("has_ip_address", "has_punycode", "has_port", "has_suspicious_keyword", "suspicious_keyword_count", "has_url_shortener", "has_double_slash_redirect_pattern", "uses_https", "count_subdomains", "url_length") if feature_map[name]]
        return {"prediction": int(is_phishing), "label": "Phishing" if is_phishing else "Legitimate", "model_score": score, "threshold": threshold, "features": feature_map, "relevant_indicators": relevant, "model_name": self.bundle.get("algorithm")}

