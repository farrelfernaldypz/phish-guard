# Dataset notes

## Preferred source

PhiUSIIL Phishing URL (Website) dataset, UCI Machine Learning Repository, dataset 967: https://archive.ics.uci.edu/dataset/967/phiusil%2Bphishing%2Burl%2Bdataset

Citation: Prasad, A. & Chandra, S. (2024). *PhiUSIIL Phishing URL (Website) [Dataset]*. UCI Machine Learning Repository. https://doi.org/10.1016/j.cose.2023.103545.

UCI lists the dataset under CC BY 4.0. Retain attribution and check the source page for current terms before redistribution.

## Source inspection and use

The UCI metadata identifies `URL` as the raw URL field and `label` as the class field. It specifies label 1 as legitimate and label 0 as phishing. It reports 235,795 instances (134,850 legitimate and 100,945 phishing) and no missing values. These are repository metadata, not statistics computed from a local copy. No dataset CSV is bundled with this project, so local schema, duplicates, missingness, and class counts must be confirmed by the training loader when you provide the file.

PhiUSIIL includes webpage-derived features alongside URL fields. PhishGuard trains solely on `URL`, computes the defined 21 URL-string features locally, and discards all precomputed feature columns. Do not describe this model as using HTML, page content, or the full PhiUSIIL feature set.

## Add and inspect data

Place the downloaded CSV in `dataset/raw/`. Example expected source columns are `URL` and `label`; training validates the names and prints an error with available columns when they differ. No raw data is checked into Git.

```powershell
python training/train.py --dataset dataset/raw/PhiUSIIL_Phishing_URL_Dataset.csv --url-column URL --label-column label --phishing-label 0 --legitimate-label 1
```

For custom datasets, supply exact column names and raw label values. The CLI mapping maps phishing to internal 1 and legitimate to internal 0.

## Preparation performed

- Drops rows with missing URL or label.
- Strips URL whitespace and removes empty URLs.
- Removes duplicate URL strings, keeping the first row.
- Requires an explicit two-class mapping; unmapped labels fail with an error.
- Reports raw and cleaned row counts and class distributions.
- Prefers domain/host-grouped 70/15/15 splits; uses a deterministic stratified row split and records that limitation when grouped splits are not feasible.

URL text parsing is offline. No DNS or HTTP access occurs during dataset loading, feature extraction, training, or inference.

