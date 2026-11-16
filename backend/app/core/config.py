from pathlib import Path
import os
PROJECT_ROOT = Path(os.getenv("PHISHGUARD_PROJECT_ROOT", Path(__file__).resolve().parents[3]))
FRONTEND_DIR = PROJECT_ROOT / "frontend"
_default_model = PROJECT_ROOT / "artifacts/model/phishguard_model.joblib"
if not _default_model.is_file() and (PROJECT_ROOT / "artifacts/model/model_phishing.pkl").is_file():
    _default_model = PROJECT_ROOT / "artifacts/model/model_phishing.pkl"
MODEL_PATH = Path(os.getenv("PHISHGUARD_MODEL_PATH", _default_model))
EVALUATION_PATH = PROJECT_ROOT / "artifacts/evaluation/metrics.json"
APP_VERSION = "1.0.0"
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "30"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))

