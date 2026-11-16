# PhishGuard model card

## Intended use

A defensive research and learning tool that scores a submitted HTTP or HTTPS URL based on URL string characteristics. It is not a browser safety product, blocklist, threat intelligence feed, or replacement for security review.

## Model and features

The training pipeline compares Logistic Regression with StandardScaler and balanced class weights against a balanced Random Forest. The winning model is selected using validation F1, with recall and precision tie-breaks. A threshold is selected on validation data to favor recall using F2. The untouched test set is used only for final metrics.

Features cover URL length and components, punctuation and character counts, host/IP/Punycode/port/HTTPS attributes, configured suspicious terms, known shortener hostnames, and a double slash path pattern. The same extractor is used in both training and API inference.

## Score meaning

The API reports the positive-class output of scikit-learn predict_proba as a **model score**. It is not presented as a calibrated probability. The selected threshold is saved with the artifact.

## Limitations and risks

- Detection depends on the quality, age, and collection bias of the labeled dataset.
- URL text features cannot assess page contents, redirects, DNS, certificates, domain reputation, or current threat feeds.
- The model can miss novel phishing and may flag legitimate URLs.
- Host based splits reduce leakage but do not guarantee geographic, temporal, or campaign independence.
- An HTTPS URL can still be malicious; a Legitimate prediction is not a safety guarantee.
- Model artifacts are Python Joblib files. Only load artifacts produced by a trusted training process and deploy compatible dependency versions.

## Privacy and security

URLs are validated and analyzed as text. The API does not fetch URLs or persist them. Operators should review reverse proxy and hosting access logs, because infrastructure may log request paths or bodies depending on configuration. Rate limiting is per process and client address; deployments behind a proxy must configure trusted proxy handling carefully.

