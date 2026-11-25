from pathlib import Path
import os
PROJECT_ROOT = Path(os.getenv("PHISHGUARD_PROJECT_ROOT", Path(__file__).resolve().parents[3]))
FRONTEND_DIR = PROJECT_ROOT / "frontend"
_default_model = PROJECT_ROOT / "artifacts/model/model_phishing_v2.pkl"
if not _default_model.is_file():
    _default_model = PROJECT_ROOT / "artifacts/model/phishguard_model.joblib"
if not _default_model.is_file() and (PROJECT_ROOT / "artifacts/model/model_phishing.pkl").is_file():
    _default_model = PROJECT_ROOT / "artifacts/model/model_phishing.pkl"
_env_model = os.getenv("PHISHGUARD_MODEL_PATH")
if _env_model and Path(_env_model).is_file():
    MODEL_PATH = Path(_env_model)
elif _env_model and (PROJECT_ROOT / "artifacts/model" / Path(_env_model).name).is_file():
    MODEL_PATH = PROJECT_ROOT / "artifacts/model" / Path(_env_model).name
else:
    MODEL_PATH = _default_model
_v2_eval = PROJECT_ROOT / "artifacts/evaluation/metrics_v2.json"
EVALUATION_PATH = _v2_eval if _v2_eval.is_file() else (PROJECT_ROOT / "artifacts/evaluation/metrics.json")
APP_VERSION = "1.0.0"
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "30"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))

