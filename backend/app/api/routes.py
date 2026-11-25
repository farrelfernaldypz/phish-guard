from fastapi import APIRouter, HTTPException, Request
import json
from time import perf_counter
from ..schemas.prediction import PredictionRequest, InvestigationRequest
from ..core.config import EVALUATION_PATH
from ..services.url_validator import URLValidationError, normalize_url
router = APIRouter(prefix="/api")

@router.get("/health")
def health(request: Request) -> dict:
    service = request.app.state.prediction_service
    return {"status": "ok", "model_status": "ready" if service.ready else "not_ready"}

@router.get("/model-info")
def model_info(request: Request) -> dict:
    return request.app.state.prediction_service.model_info()

@router.get("/metrics")
def metrics() -> dict:
    if not EVALUATION_PATH.is_file():
        raise HTTPException(status_code=404, detail="Evaluation metrics are not available.")
    try:
        payload = json.loads(EVALUATION_PATH.read_text(encoding="utf-8"))
        if "test_metrics" not in payload and "test_metrics_phiusiil" in payload:
            payload["test_metrics"] = payload["test_metrics_phiusiil"]
        return payload
    except (OSError, json.JSONDecodeError) as error:
        raise HTTPException(status_code=503, detail="Evaluation metrics could not be loaded.") from error

@router.post("/predict")
def predict(payload: PredictionRequest, request: Request) -> dict:
    service = request.app.state.prediction_service
    investigator = getattr(request.app.state, "server_investigator", None)
    if not service.ready:
        raise HTTPException(status_code=503, detail="PhishGuard is not ready to predict: trained model unavailable.")
    try:
        started_at = perf_counter()
        normalized = normalize_url(payload.url)
        result = service.predict(normalized)
        
        # Attach instant brand intelligence (0 ms)
        if investigator:
            result["brand_intelligence"] = investigator.identify_brand(normalized)
            if payload.deep_investigate:
                result["investigation"] = investigator.investigate(normalized)

        result["processing_time_ms"] = round((perf_counter() - started_at) * 1000, 3)
    except URLValidationError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    except RuntimeError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    return {"url": normalized, **result}

@router.post("/investigate")
def investigate(payload: InvestigationRequest, request: Request) -> dict:
    investigator = getattr(request.app.state, "server_investigator", None)
    if not investigator:
        raise HTTPException(status_code=503, detail="Investigation engine is not available.")
    try:
        started_at = perf_counter()
        normalized = normalize_url(payload.url)
        report = investigator.investigate(normalized)
        report["processing_time_ms"] = round((perf_counter() - started_at) * 1000, 3)
        return report
    except URLValidationError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    except Exception as error:
        raise HTTPException(status_code=500, detail=f"Gagal melakukan investigasi: {error}") from error

