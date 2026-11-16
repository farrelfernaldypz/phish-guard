# Development of a Machine Learning-Based Phishing URL Detection System

## 1. Pendahuluan
Tuliskan konteks keamanan tautan dan ruang lingkup proyek.

### 1.1 Latar belakang
Jelaskan risiko phishing berbasis URL dan alasan analisis karakteristik URL dipilih. Sertakan sitasi akademis dan sumber dataset.

### 1.2 Rumusan masalah
1. Bagaimana URL mentah dapat diubah menjadi fitur numerik yang konsisten?
2. Bagaimana Logistic Regression dan Random Forest dibandingkan untuk klasifikasi URL phishing?
3. Bagaimana sistem menyajikan hasil secara aman tanpa mengakses URL yang dianalisis?

### 1.3 Tujuan
- Mengimplementasikan ekstraksi fitur URL tanpa koneksi jaringan.
- Melatih dan membandingkan dua algoritma supervised learning pada data berlabel.
- Menyediakan aplikasi web dan API untuk inferensi lokal.

## 2. Metode
### 2.1 Dataset dan lisensi
Catat sumber, versi, tanggal unduh, atribusi, kolom URL dan label yang diperiksa, pemetaan label, jumlah data, class distribution, missing values, duplicates, dan lisensi aktual.

### 2.2 Preprocessing dan pembagian data
Jelaskan cleaning, deduplikasi, normalisasi label, random state, split aktual, host grouping, serta fallback bila host grouping tidak layak.

### 2.3 Ekstraksi fitur
Jelaskan 21 fitur dan bagaimana skema yang sama digunakan pada training dan inference.

### 2.4 Pelatihan dan pemilihan model
Catat konfigurasi Logistic Regression dan Random Forest, hasil validation, aturan pemilihan, threshold validation, serta versi library.

### 2.5 Implementasi sistem
Uraikan FastAPI, frontend vanilla, perlindungan input, batasan request, rate limit, Docker, dan reverse proxy.

## 3. Pembahasan
Masukkan hasil aktual dari `artifacts/evaluation/evaluation.md`. Sajikan accuracy, precision, recall, F1, confusion matrix, false positive, false negative, ROC-AUC dan PR-AUC jika tersedia. Analisis error dan kemungkinan leakage, bias, temporal drift, serta generalisasi. Jangan menyalin metrik sebelum training dan test selesai.

## 4. Kesimpulan
Ringkas temuan berdasarkan hasil aktual, jawab rumusan masalah, dan nyatakan batasan sistem. Jangan menyatakan bahwa sistem menjamin keamanan atau mendeteksi seluruh phishing.

## Referensi
Cantumkan sumber dataset, paper algoritma/metode, dokumentasi software yang relevan, serta tanggal akses.

