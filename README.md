# PhishGuard
### Cybersecurity for Everyone

PhishGuard merupakan sistem keamanan siber yang dirancang untuk membantu masyarakat, khususnya pengguna dengan pemahaman teknologi yang masih terbatas, dalam mengenali dan menghindari potensi ancaman kejahatan siber.

PhishGuard menyediakan tiga fitur utama untuk memeriksa potensi ancaman digital:

- **URL Scanner** — Memeriksa tautan mencurigakan sebelum pengguna mengaksesnya.
- **QR Shield** — Membaca QR Code dan memeriksa keamanan tautan yang terkandung di dalamnya.
- **MailGuard** — Menganalisis email mencurigakan untuk membantu mengidentifikasi indikasi phishing.

Selain itu, PhishGuard dilengkapi dengan Threat Watchlist untuk mengelola daftar domain yang perlu diwaspadai serta Scan History untuk melihat riwayat pemeriksaan.

---

## 1. Persyaratan Sistem

Sebelum menjalankan PhishGuard, pastikan perangkat memiliki:

| Komponen | Persyaratan |
|---|---|
| Operating System | Windows 10 / Windows 11 |
| Python | Python 3.10 atau lebih baru |
| RAM | Minimal 4 GB |
| Browser | Google Chrome, Microsoft Edge, atau browser modern lainnya |
| Internet | Disarankan tersedia untuk kebutuhan tertentu |

Pastikan Python sudah terinstal dan dapat diakses melalui terminal.

Untuk memeriksa instalasi Python, buka Command Prompt atau PowerShell dan jalankan:

```bash
python --version
```

Jika versi Python muncul, berarti instalasi berhasil.

Jika perintah tersebut tidak dikenali, instal Python terlebih dahulu melalui:
https://www.python.org/downloads/

Saat instalasi, pastikan opsi **Add Python to PATH** dicentang.

---

## 2. Instalasi PhishGuard

### Langkah 1 — Ekstrak File ZIP

1. Unduh file ZIP PhishGuard yang disediakan.
2. Klik kanan file ZIP.
3. Pilih **Extract All**.
4. Tentukan lokasi penyimpanan.
5. Buka folder PhishGuard yang sudah diekstrak.

Pastikan file `app.py` dan `requirements.txt` berada di dalam folder utama proyek.

### Langkah 2 — Buka Terminal

1. Buka folder PhishGuard.
2. Klik pada address bar File Explorer.
3. Ketik `cmd`.
4. Tekan Enter.

Command Prompt akan terbuka langsung pada direktori PhishGuard.

### Langkah 3 — Buat Virtual Environment

Jalankan perintah berikut:

```bash
python -m venv venv
```

Aktifkan virtual environment:

```bash
venv\Scripts\activate
```

Jika berhasil, akan muncul tanda `(venv)` pada awal baris terminal.

### Langkah 4 — Instal Dependency

Pastikan virtual environment sudah aktif, kemudian jalankan:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Tunggu hingga seluruh dependency selesai diinstal.

### Langkah 5 — Jalankan PhishGuard

Setelah instalasi selesai, jalankan:

```bash
python app.py
```

Jika aplikasi berhasil berjalan, terminal akan menampilkan alamat lokal, biasanya:

```text
http://127.0.0.1:5000
```

Buka browser dan akses alamat tersebut.

**PhishGuard sekarang siap digunakan.**

---

## 3. Panduan Penggunaan Fitur

### A. Dashboard

Dashboard merupakan halaman utama PhishGuard yang menampilkan ringkasan aktivitas pemeriksaan keamanan.

Informasi yang tersedia meliputi:
- Total pemeriksaan.
- Jumlah ancaman dengan kategori risiko tinggi.
- Jumlah ancaman dengan kategori risiko sedang.
- Jumlah ancaman dengan kategori risiko rendah.
- Ringkasan aktivitas pemeriksaan terbaru.

Gunakan halaman ini untuk melihat gambaran umum aktivitas sistem.

### B. URL Scanner

URL Scanner digunakan untuk memeriksa tautan yang dianggap mencurigakan.

**Cara penggunaan:**

1. Buka menu URL Scanner.
2. Masukkan URL yang ingin diperiksa pada kolom yang tersedia.
3. Klik tombol Scan atau Check.
4. Tunggu hingga proses analisis selesai.
5. Perhatikan hasil pemeriksaan yang ditampilkan.

Hasil pemeriksaan dapat memberikan informasi seperti:
- Alamat URL dan hostname.
- Skor risiko.
- Kategori risiko.
- Temuan atau indikator mencurigakan.
- Rekomendasi tindakan.

Jangan langsung membuka tautan yang terindikasi berbahaya.

### C. QR Shield

QR Shield digunakan untuk memeriksa QR Code yang mungkin mengarahkan pengguna ke situs berbahaya.

**Cara penggunaan:**

1. Buka menu QR Shield.
2. Siapkan gambar QR Code dalam format gambar yang didukung, seperti PNG atau JPG.
3. Unggah gambar melalui fitur upload.
4. Jalankan proses pemindaian.
5. Sistem akan mencoba membaca QR Code dan mengambil tautan yang terkandung di dalamnya.
6. Jika berhasil dibaca, tautan akan dianalisis untuk mengetahui potensi risikonya.
7. Perhatikan hasil pemeriksaan yang ditampilkan.

**Catatan:** Pastikan gambar QR Code terlihat jelas, tidak terpotong, dan memiliki kualitas yang cukup agar dapat dibaca oleh sistem.

### D. MailGuard

MailGuard membantu pengguna menganalisis email yang memiliki indikasi mencurigakan atau berpotensi phishing.

**Cara penggunaan:**

1. Buka menu MailGuard.
2. Masukkan atau tempelkan konten email yang ingin diperiksa sesuai kolom yang tersedia.
3. Jalankan proses analisis.
4. Tunggu hingga sistem menyelesaikan pemeriksaan.
5. Perhatikan hasil analisis dan indikator mencurigakan yang ditemukan.

Gunakan fitur ini untuk membantu mengevaluasi email yang berasal dari pengirim tidak dikenal atau memiliki isi pesan yang mencurigakan.

### E. Threat Watchlist

Threat Watchlist digunakan untuk mengelola daftar domain yang perlu diwaspadai.

**Cara penggunaan:**

1. Buka menu Threat Watchlist.
2. Periksa daftar domain yang sudah tersedia.
3. Untuk menambahkan domain, masukkan domain dan deskripsinya pada formulir yang tersedia.
4. Simpan data tersebut.
5. Untuk menghapus entri, gunakan tombol hapus pada entri yang ingin dihilangkan.

Fitur ini membantu pengguna menyimpan dan memantau domain yang dianggap mencurigakan.

### F. Scan History

Scan History digunakan untuk melihat riwayat pemeriksaan yang telah dilakukan.

**Cara penggunaan:**

1. Buka menu Scan History.
2. Sistem akan menampilkan daftar pemeriksaan sebelumnya.
3. Perhatikan jenis pemeriksaan, target, skor risiko, tingkat risiko, dan waktu pemeriksaan yang tersedia.

Riwayat ini dapat digunakan untuk memantau aktivitas pemeriksaan yang telah dilakukan.

---

## 4. Interpretasi Hasil Pemeriksaan

PhishGuard mengelompokkan hasil analisis berdasarkan tingkat risiko.

| Kategori | Interpretasi |
|---|---|
| Low Risk | Indikator risiko yang ditemukan relatif rendah. |
| Medium Risk | Terdapat beberapa indikator mencurigakan yang perlu diperhatikan. |
| High Risk | Ditemukan indikator risiko tinggi yang memerlukan kewaspadaan lebih lanjut. |

**Penting:** Kategori risiko merupakan hasil analisis sistem berdasarkan indikator yang tersedia. Hasil Low Risk bukan jaminan bahwa suatu URL, QR Code, atau email sepenuhnya aman.

---

## 5. Menghentikan Aplikasi

Jika ingin menghentikan PhishGuard:

1. Kembali ke jendela terminal tempat aplikasi berjalan.
2. Tekan `CTRL + C`.
3. Aplikasi akan berhenti.

Untuk menjalankan kembali, aktifkan virtual environment jika belum aktif, kemudian jalankan:

```bash
python app.py
```

---

## 6. Troubleshooting

| Permasalahan | Solusi |
|---|---|
| `python is not recognized` | Pastikan Python sudah terinstal dan masuk ke PATH. |
| `No module named ...` | Jalankan kembali `pip install -r requirements.txt`. |
| `Could not open requirements.txt` | Pastikan terminal berada di folder utama PhishGuard. |
| `Address already in use` | Port 5000 sedang digunakan aplikasi lain. Hentikan aplikasi tersebut terlebih dahulu. |
| QR Code tidak terbaca | Gunakan gambar QR Code yang lebih jelas dan tidak terpotong. |
| Database error | Pastikan struktur database sesuai dengan versi aplikasi yang digunakan. |

Jika terjadi kesalahan saat menjalankan aplikasi, periksa pesan error pada terminal.

---

## 7. Teknologi yang Digunakan

PhishGuard dikembangkan menggunakan teknologi berikut:

- **Python** — Bahasa pemrograman utama.
- **Flask** — Framework web untuk menjalankan aplikasi.
- **SQLite** — Database untuk menyimpan data pemeriksaan dan Watchlist.
- **HTML** — Struktur halaman web.
- **CSS** — Tampilan dan desain antarmuka.
- **JavaScript** — Interaksi pada sisi pengguna.
- **OpenCV** — Mendukung proses pembacaan QR Code.

---

## 8. Catatan Keamanan dan Batasan Sistem

PhishGuard merupakan alat bantu pemeriksaan keamanan digital dan bukan pengganti antivirus, firewall, atau layanan keamanan profesional.

Hasil pemeriksaan tidak menjamin bahwa seluruh ancaman dapat terdeteksi. Pengguna tetap disarankan untuk berhati-hati ketika membuka tautan, memindai QR Code, maupun merespons email yang tidak dikenal.

Untuk keperluan demonstrasi dan penilaian, gunakan data pengujian yang tidak mengandung informasi pribadi atau kredensial asli.

---

## 9. Penutup

PhishGuard hadir dengan tujuan menjadikan keamanan siber lebih mudah dipahami dan diakses oleh semua orang.

Melalui pemeriksaan URL, QR Code, dan email, PhishGuard diharapkan dapat membantu meningkatkan kesadaran serta kewaspadaan pengguna terhadap ancaman kejahatan siber.

**PhishGuard — Cybersecurity for Everyone.**

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
