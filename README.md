# PhishGuard MVP

Prototype web untuk menganalisis karakteristik URL menggunakan aturan heuristik lokal.

## Fitur MVP
- Input dan validasi URL
- Analisis indikator URL
- Risk score 0–100
- Hasil analisis dan rekomendasi
- Riwayat pemeriksaan menggunakan SQLite

## Persyaratan
- Python 3.11+
- pip

## Instalasi (Windows PowerShell)

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python app.py
```

Jika PowerShell memblokir aktivasi environment, jalankan:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

Kemudian buka `http://127.0.0.1:5000`.

## Instalasi (macOS / Linux)

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python app.py
```

## Catatan penting
- Aplikasi ini hanya menganalisis teks dan struktur URL secara lokal.
- Aplikasi TIDAK mengunjungi URL yang dimasukkan pengguna.
- Skor merupakan heuristik prototype, bukan standar industri atau jaminan keamanan.
- Jangan memasukkan URL privat atau sensitif ke layanan pihak ketiga.
- Sebelum deployment publik, ganti `secret_key`, matikan debug mode, tambahkan rate limiting, validasi keamanan tambahan, dan gunakan server WSGI produksi.
