# Evaluation

No dataset or trained model is included in the initial workspace. Therefore no measured metrics are available yet and no evaluation numbers are claimed.

After supplying labeled data and running the training command in README, the script writes the actual held-out test report to `artifacts/evaluation/metrics.json` and `artifacts/evaluation/evaluation.md`, plus plots for the confusion matrix, validation model comparison, and test metrics. The generated report records dataset counts, class distribution, split sizes and strategy, model comparison, selected model, threshold, accuracy, precision, recall, F1, false positives, false negatives, ROC-AUC, and PR-AUC where defined.

Threshold selection and algorithm comparison use validation data only. Test metrics are calculated once after the selection step. Read the generated report together with the dataset limitations before interpreting performance.

