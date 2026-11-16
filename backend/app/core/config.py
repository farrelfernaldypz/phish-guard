from pathlib import Path
import os
PROJECT_ROOT = Path(os.getenv("PHISHGUARD_PROJECT_ROOT", Path(__file__).resolve().parents[3]))
FRONTEND_DIR = PROJECT_ROOT / "frontend"
MODEL_PATH = Path(os.getenv("PHISHGUARD_MODEL_PATH", PROJECT_ROOT / "artifacts/model/phishguard_model.joblib"))
EVALUATION_PATH = PROJECT_ROOT / "artifacts/evaluation/metrics.json"
APP_VERSION = "1.0.0"
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "30"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))

