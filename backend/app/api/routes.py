from fastapi import APIRouter, HTTPException, Request
import json
from time import perf_counter
from ..schemas.prediction import PredictionRequest
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
        return json.loads(EVALUATION_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise HTTPException(status_code=503, detail="Evaluation metrics could not be loaded.") from error

@router.post("/predict")
def predict(payload: PredictionRequest, request: Request) -> dict:
    service = request.app.state.prediction_service
    if not service.ready:
        raise HTTPException(status_code=503, detail="PhishGuard is not ready to predict: trained model unavailable.")
    try:
        started_at = perf_counter()
        normalized = normalize_url(payload.url)
        result = service.predict(normalized)
        result["processing_time_ms"] = round((perf_counter() - started_at) * 1000, 3)
    except URLValidationError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    except RuntimeError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    return {"url": normalized, **result}

