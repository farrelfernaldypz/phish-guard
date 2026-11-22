# PhishGuard

Machine learning based phishing URL analysis using locally trained scikit-learn classifiers. PhishGuard extracts URL text features only. It never resolves, fetches, crawls, or opens a submitted URL, and it does not call external AI or threat detection services.

**Current model state:** no dataset or trained artifact is included. The scanner stays disabled until a valid model bundle is created by a real training run.

## Project structure

```text
frontend/                  Static HTML, CSS, and vanilla JavaScript
backend/app/               FastAPI routes, validation, feature extraction, inference
training/                  CSV loading, preprocessing, training, evaluation
dataset/raw/               User-provided dataset files (not committed)
dataset/processed/         Optional generated data (not committed)
artifacts/model/           Trained Joblib bundle (not committed)
artifacts/evaluation/      Actual JSON, Markdown, and plots from training
tests/                     Pytest feature and API tests
docs/                      Dataset, model, evaluation, deployment, team, report docs
deploy/                    Reverse proxy examples
docker-compose.yml         Local and VPS container setup
```

## Requirements and local setup

Use Python 3.11. From the project root:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r backend/requirements.txt
Copy-Item .env.example .env
```

On Linux or macOS, activate with `source .venv/bin/activate`.

## Dataset

Download the PhiUSIIL Phishing URL Dataset from the [UCI Machine Learning Repository](https://archive.ics.uci.edu/dataset/967/phiusil%2Bphishing%2Burl%2Bdataset) and place its CSV at `dataset/raw/PhiUSIIL_Phishing_URL_Dataset.csv`. The repository metadata lists `URL` and `label`; label 1 is legitimate and label 0 is phishing, and the dataset is CC BY 4.0. It contains additional features extracted from website content. PhishGuard intentionally ignores those columns and trains from the raw URL column alone; this project does not claim to reproduce the dataset's website-derived signals. See [docs/DATASET.md](docs/DATASET.md).

For another labeled CSV, provide its URL and label column names and explicit raw label mapping.

## Train and evaluate (Cloud-Based MLOps Architecture)

Untuk menjaga performa dan melindungi sumber daya komputer lokal, proses **pelatihan model (training) dilakukan sepenuhnya di Cloud (Google Colab / Kaggle)**, bukan di komputer lokal.

1. Buka [Google Colab](https://colab.research.google.com/) dan unggah notebook `training/PhishGuard_Model_Training_Colab.ipynb`.
2. Jalankan seluruh sel di Colab untuk mengunduh dataset PhiUSIIL (235k URL), mengekstrak 11 fitur leksikal + pola ancaman lokal Indonesia, dan melatih ensemble `RandomForestClassifier` (100 Decision Trees).
3. Unduh hasil artefak model dan letakkan di:
   - `artifacts/model/model_phishing.pkl`
   - `artifacts/evaluation/metrics.json`
4. Komputer lokal murni bertindak sebagai **Inference Engine** yang super ringan (<30ms per scan, memory footprint rendah) tanpa beban proses training sama sekali.

## Run the app

```powershell
python -m uvicorn app.main:app --app-dir backend --env-file .env --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000. The page shows model readiness and actual test metrics if present. API endpoints are `GET /api/health`, `GET /api/model-info`, `GET /api/metrics`, and `POST /api/predict`. The predict body is `{"url":"https://example.com"}`. A model score is a classifier score, not a calibrated probability. When no valid model exists, prediction returns HTTP 503.

## Tests

```powershell
python -m pytest -q
```

## Docker

After training and generating the model artifact:

```powershell
docker compose up --build -d
docker compose logs -f
```

Compose binds the app to localhost port 8000 for a reverse proxy. See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for Ubuntu VPS, Caddy HTTPS, and operational setup. Docker is not installed in the current development environment, so container execution has not been verified here.

## Limitations

The model is only as representative as the data used to train and evaluate it. URL-only character and structure features miss page content, live reputation, redirects, and newly created campaigns. A legitimate classification is not proof of safety, and a phishing classification is not a definitive verdict. Scores are not calibrated probabilities. The service does not store submitted URLs by default.

