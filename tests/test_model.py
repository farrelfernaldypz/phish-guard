import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import joblib
from backend.app.services.feature_extraction import FEATURE_NAMES
from backend.app.services.prediction import PredictionService

class FixedScoreModel:
    classes_ = [0, 1]
    def predict_proba(self, matrix):
        return [[0.2, 0.8] for _ in matrix]

def test_model_bundle_loads_with_expected_feature_order(tmp_path):
    artifact = tmp_path / "model.joblib"
    joblib.dump({"model": FixedScoreModel(), "feature_names": FEATURE_NAMES, "threshold": 0.6, "algorithm": "test"}, artifact)
    service = PredictionService(artifact)
    assert service.ready
    assert service.model_info()["feature_names"] == FEATURE_NAMES

def test_threshold_controls_valid_prediction(tmp_path):
    artifact = tmp_path / "model.joblib"
    joblib.dump({"model": FixedScoreModel(), "feature_names": FEATURE_NAMES, "threshold": 0.9, "algorithm": "test"}, artifact)
    result = PredictionService(artifact).predict("https://example.com")
    assert result["prediction"] == 0
    assert result["label"] == "Legitimate"
    assert result["model_score"] == 0.8


class FixedTfidfClassifier:
    classes_ = [0, 1]
    def predict_proba(self, matrix):
        return [[0.15, 0.85] for _ in range(matrix.shape[0])]


class FixedTfidfVectorizer:
    def transform(self, texts):
        import numpy as np
        return np.zeros((len(texts), 3))


def test_v2_bundle_with_tfidf_and_27_features(tmp_path):
    from backend.app.services.feature_extraction import extract_v2_tabular_features
    v2_cols = list(extract_v2_tabular_features("https://example.com").keys()) + ["tfidf_char_prob"]
    artifact = tmp_path / "model_v2.pkl"
    joblib.dump(
        {
            "model": FixedScoreModel(),
            "tfidf_vectorizer": FixedTfidfVectorizer(),
            "tfidf_classifier": FixedTfidfClassifier(),
            "feature_names": v2_cols,
            "threshold": 0.5,
            "algorithm": "LightGBM (v2 Test)",
            "metadata": {"version": "2.0-data-centric"},
        },
        artifact,
    )
    service = PredictionService(artifact)
    assert service.ready
    res = service.predict("https://g00gle-verify.com/auth", resolve_redirects=False)
    assert res["prediction"] == 1
    assert res["features"]["tfidf_char_prob"] == 0.85
    assert res["features"]["typosquat_similarity"] == 1.0
    assert "typosquatting_brand_similarity" in res["relevant_indicators"]


def test_real_v2_artifact_inference_if_present():
    v2_path = Path(__file__).resolve().parents[1] / "artifacts/model/model_phishing_v2.pkl"
    if not v2_path.is_file():
        return
    service = PredictionService(v2_path)
    assert service.ready
    assert len(service.model_info()["feature_names"]) == 27
    safe_res = service.predict("https://docs.python.org/3/library/urllib.parse.html", resolve_redirects=False)
    assert safe_res["prediction"] == 0
    phish_res = service.predict("https://dana-kaget-gratis-2026.xyz/", resolve_redirects=False)
    assert phish_res["prediction"] == 1
