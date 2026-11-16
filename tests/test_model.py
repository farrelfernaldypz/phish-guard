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
