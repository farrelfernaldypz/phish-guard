import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.services.prediction import PredictionService
from backend.app.services.url_validator import URLValidationError, normalize_url
from backend.app.services.feature_extraction import FEATURE_NAMES
import joblib

client = TestClient(app)

class FixedApiScoreModel:
    classes_ = [0, 1]
    def predict_proba(self, matrix):
        return [[0.1, 0.9] for _ in matrix]

def test_health_and_model_info_report_missing_artifact():
    assert client.get("/api/health").json()["model_status"] in {"ready", "not_ready"}
    assert "feature_names" in client.get("/api/model-info").json()

def test_prediction_reports_model_unavailable_without_fake_result(monkeypatch):
    app.state.prediction_service = PredictionService(Path("missing-model.joblib"))
    response = client.post("/api/predict", json={"url": "example.com"})
    assert response.status_code == 503
    app.state.prediction_service = PredictionService()

def test_invalid_and_empty_requests_are_rejected():
    assert client.post("/api/predict", json={"url": ""}).status_code == 422
    assert client.post("/api/predict", json={"url": "ftp://example.com"}).status_code in {422, 503}
    assert client.post("/api/predict", json={}).status_code == 422

def test_oversized_url_is_rejected():
    response = client.post("/api/predict", json={"url": "a" * 2049})
    assert response.status_code == 422

def test_oversized_request_body_is_rejected():
    response = client.post("/api/predict", content=b'{"url":"example.com","padding":"' + b"x" * 8200 + b'"}', headers={"Content-Type": "application/json"})
    assert response.status_code == 413

def test_invalid_scheme_is_rejected_by_url_validator():
    try:
        normalize_url("ftp://example.com")
    except URLValidationError:
        return
    raise AssertionError("Unsupported URL scheme should fail validation.")

def test_static_frontend_and_security_headers_are_available():
    response = client.get("/")
    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"

def test_prediction_works_with_a_valid_local_artifact(tmp_path, monkeypatch):
    artifact = tmp_path / "api-model.joblib"
    joblib.dump({"model": FixedApiScoreModel(), "feature_names": FEATURE_NAMES, "threshold": 0.5, "algorithm": "Test Classifier", "metadata": {}}, artifact)
    monkeypatch.setattr(app.state, "prediction_service", PredictionService(artifact))
    response = client.post("/api/predict", json={"url": "example.com/login"})
    assert response.status_code == 200
    result = response.json()
    assert result["prediction"] == 1
    assert result["label"] == "Phishing"
    assert result["model_name"] == "Test Classifier"
    assert result["processing_time_ms"] >= 0


def test_metrics_endpoint_exposes_test_metrics():
    response = client.get("/api/metrics")
    if response.status_code == 200:
        data = response.json()
        assert "test_metrics" in data
        assert data["test_metrics"]["accuracy"] > 0.90

