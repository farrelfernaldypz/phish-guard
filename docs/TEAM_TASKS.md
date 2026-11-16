# Team tasks

## Member 1 — Machine Learning Engineer
- Acquire and cite the labeled dataset; inspect its actual columns, license, labels, duplicates, missingness, and class distribution.
- Review preprocessing and host-group split feasibility.
- Maintain the shared feature extraction schema.
- Train and compare Logistic Regression and Random Forest.
- Review validation threshold selection, held-out metrics, false positives, false negatives, and limitations.

## Member 2 — Backend Developer
- Maintain FastAPI health, prediction, model information, and metrics endpoints.
- Own input normalization, request validation, rate limiting, error responses, model artifact loading, and API tests.
- Confirm submitted URLs are never fetched or written to application logs.

## Member 3 — Frontend and Deployment Developer
- Maintain semantic HTML, responsive CSS, accessible scanner feedback, and safe text-only rendering.
- Integrate the frontend with the local API and display actual model/evaluation metadata only.
- Own Docker Compose, Ubuntu VPS setup, reverse proxy, TLS, and operational deployment documentation.

## Shared integration
All members review the feature order and API contract together. Before release, jointly run the complete test suite, inspect the generated evaluation report, exercise the no-model state, and verify the deployed service over HTTPS. No member should publish dataset or model files without checking license and repository size/privacy requirements.

