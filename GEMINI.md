# PhishGuard Workspace Rules (Locked Project Identity)

## Identitas & Tagline Resmi Proyek (WAJIB DIKUNCI)
Setiap pembaruan kode, dokumentasi, README, laporan akademik, maupun antarmuka UI **wajib mempertahankan** narasi inti berikut tanpa mengubah maknanya:

> **PhishGuard, sebuah terobosan dalam deteksi phishing berbasis URL menggunakan pendekatan Data-Centric AI dan Machine Learning Generasi Lanjutan**

## Prinsip Arsitektur yang Dikunci
1. **Pendekatan Data-Centric AI:** Menggunakan dataset benchmark PhiUSIIL yang diperkaya dengan *Data-Centric Augmentation* (sampel URL aman multi-path/HTTP/dokumentasi serta tautan phishing lokal Indonesia dan *live feed* OpenPhish pada data latih) untuk menghilangkan bias protokol `has_https`.
2. **Machine Learning Generasi Lanjutan (PhishGuard v2):** Menggunakan arsitektur *Stacked Hybrid* (**Character N-Gram TF-IDF** pada URL tanpa prefix skema + **27 dimensi fitur leksikal, statistik, dan Fuzzy Typosquatting** + **`LightGBM (LGBMClassifier)`**) yang dipadukan dengan lapisan *Hybrid Defense-in-Depth* (Safe Unshortener, Domain-Decomposed Scoring, Whitelist, Brand Intelligence, dan Heuristic Guardrails).
3. **Kompatibilitas & Integritas:** Seluruh pembaruan ke depan harus tetap menjaga kesesuaian pipeline fitur antara notebook training (`PhishGuard_Model_Training_Colab_v2.ipynb`), backend inferensi (`backend/app/services/`), serta seluruh pengujian otomatis di `tests/`.
