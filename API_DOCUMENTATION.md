# PhishGuard REST API Specification

> **Base URL:** `http://localhost:5000`  
> **API Prefix:** `/api`  
> **CORS Origin (Dev):** `http://localhost:5173`  
> **Standard Response Envelope:** All JSON responses follow the `{ "success": boolean, "data": object | array | null, "message": string }` format.

---

## Table of Contents
1. [General Response Formats & Error Codes](#general-response-formats--error-codes)
2. [System Status (`GET /api/system/status`)](#1-system-status)
3. [URL Scanner (`POST /api/url/scan`)](#2-url-scanner)
4. [QR Code Scanner (`POST /api/qr/scan`)](#3-qr-code-scanner)
5. [Email Phishing Analyzer (`POST /api/email/analyze`)](#4-email-phishing-analyzer)
6. [File Hash Checker (`POST /api/file/scan`)](#5-file-hash-checker)
7. [Threat Watchlist (`/api/watchlist`)](#6-threat-watchlist)
   - [List Watchlist Entries (`GET /api/watchlist`)](#61-list-watchlist-entries)
   - [Add Watchlist Entry (`POST /api/watchlist`)](#62-add-watchlist-entry)
   - [Delete Watchlist Entry (`DELETE /api/watchlist/<id>`)](#63-delete-watchlist-entry)
8. [Dashboard Analytics (`/api/dashboard`)](#7-dashboard-analytics)
   - [Overall Dashboard Stats (`GET /api/dashboard/stats`)](#71-overall-dashboard-stats)
   - [Activity Timeline (`GET /api/dashboard/activity`)](#72-activity-timeline)
9. [Unified Scan History (`/api/history`)](#8-unified-scan-history)
   - [List History Entries (`GET /api/history`)](#81-list-history-entries)
   - [Get History Detail (`GET /api/history/<id>`)](#82-get-history-detail)

---

## General Response Formats & Error Codes

### Standard Success Response
```json
{
  "success": true,
  "data": { ... },
  "message": "Operation completed successfully"
}
```

### Standard Error Response
```json
{
  "success": false,
  "data": null,
  "message": "Detailed error description"
}
```

### HTTP Status Codes
| Code | Meaning | Usage |
|------|---------|-------|
| `200` | OK | Request processed successfully |
| `201` | Created | Resource successfully created (e.g. Watchlist entry) |
| `400` | Bad Request | Validation error, malformed JSON, or missing required fields |
| `404` | Not Found | Requested resource ID not found |
| `409` | Conflict | Resource already exists (e.g. duplicate watchlist domain) |
| `413` | Payload Too Large | Uploaded file exceeds size limit (5MB for QR, 10MB for file hash) |
| `500` | Internal Server Error | Unhandled server error |

---

## 1. System Status

Returns the health and operational status of all backend subsystems and analysis engines.

- **HTTP Method:** `GET`
- **Endpoint URL:** `/api/system/status`
- **Request Headers:** None
- **Query Parameters:** None
- **Request Body:** None

### Success Response (`200 OK`)
```json
{
  "success": true,
  "data": {
    "status": "operational",
    "version": "2.0.0",
    "timestamp": "2026-11-15T10:15:00+07:00",
    "services": {
      "backend": {
        "status": "online",
        "framework": "Flask 3.1.3",
        "cors_origin": "http://localhost:5173"
      },
      "database": {
        "status": "online",
        "engine": "SQLite",
        "total_records": 128
      },
      "url_analyzer": {
        "status": "operational",
        "active_rules": 9,
        "offline_mode": true
      },
      "qr_analyzer": {
        "status": "operational",
        "engine": "OpenCV QRCodeDetector"
      },
      "email_analyzer": {
        "status": "operational",
        "heuristic_rules": 6
      },
      "file_analyzer": {
        "status": "operational",
        "algorithm": "SHA-256",
        "known_threat_hashes": 42
      }
    }
  },
  "message": "System status retrieved successfully"
}
```

### Error Response (`500 Internal Server Error`)
```json
{
  "success": false,
  "data": null,
  "message": "Database connection failed: disk I/O error"
}
```

---

## 2. URL Scanner

Analyzes a URL using local heuristic detection rules, checks against the local threat watchlist, calculates a risk score (0-100), and returns detailed indicator findings. Never fetches or connects to the remote URL.

- **HTTP Method:** `POST`
- **Endpoint URL:** `/api/url/scan`
- **Request Headers:** `Content-Type: application/json`
- **Query Parameters:** None
- **Request Body (JSON):**
```json
{
  "url": "http://secure-login.bank-update.xn--p1ai/verify?account=admin"
}
```

### Request Parameters
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `url` | string | Yes | The URL or domain to analyze (e.g. `https://example.com` or `example.com`) |

### Success Response (`200 OK`)
```json
{
  "success": true,
  "data": {
    "id": 45,
    "url": "http://secure-login.bank-update.xn--p1ai/verify?account=admin",
    "normalized_url": "http://secure-login.bank-update.xn--p1ai/verify?account=admin",
    "hostname": "secure-login.bank-update.xn--p1ai",
    "risk_score": 75,
    "risk_level": "High",
    "recommendation": "Jangan masukkan informasi pribadi. Verifikasi alamat melalui kanal resmi.",
    "findings": [
      {
        "label": "Host berupa alamat IP",
        "detail": "Phishing kadang menggunakan alamat IP secara langsung sebagai host.",
        "points": 0,
        "status": "Tidak ditemukan"
      },
      {
        "label": "Kata kunci sensitif",
        "detail": "URL mengandung kata yang sering dipakai dalam umpan login atau verifikasi.",
        "points": 10,
        "status": "Indikator ditemukan"
      },
      {
        "label": "Jumlah subdomain tidak biasa",
        "detail": "URL memiliki 3 subdomain (indikator sederhana: lebih dari 2).",
        "points": 10,
        "status": "Indikator ditemukan"
      },
      {
        "label": "Hostname menggunakan pola punycode",
        "detail": "Awalan xn-- dapat menunjukkan nama domain internasional yang dikodekan.",
        "points": 10,
        "status": "Indikator ditemukan"
      },
      {
        "label": "Tidak menggunakan HTTPS",
        "detail": "Koneksi HTTP tidak mengenkripsi komunikasi antara browser dan situs.",
        "points": 5,
        "status": "Indikator ditemukan"
      },
      {
        "label": "Kecocokan Threat Watchlist",
        "detail": "Domain atau URL terdaftar di database watchlist ancaman lokal.",
        "points": 40,
        "status": "Indikator ditemukan"
      }
    ],
    "watchlist_match": {
      "id": 3,
      "target": "secure-login.bank-update.xn--p1ai",
      "threat_category": "Phishing",
      "description": "Known credential harvesting site"
    },
    "created_at": "2026-11-15T10:15:30+07:00",
    "disclaimer": "Ini adalah analisis heuristik lokal, bukan jaminan bahwa URL aman atau berbahaya."
  },
  "message": "URL analysis completed successfully"
}
```

### Error Responses
**Missing or Empty URL (`400 Bad Request`):**
```json
{
  "success": false,
  "data": null,
  "message": "URL tidak boleh kosong."
}
```

**Invalid URL Format (`400 Bad Request`):**
```json
{
  "success": false,
  "data": null,
  "message": "URL tidak valid. Masukkan nama domain yang lengkap."
}
```

---

## 3. QR Code Scanner

Uploads and decodes a QR code image using OpenCV. If the encoded payload contains a valid URL, it automatically cascades the URL through the URL threat analysis engine.

- **HTTP Method:** `POST`
- **Endpoint URL:** `/api/qr/scan`
- **Request Headers:** `Content-Type: multipart/form-data`
- **Query Parameters:** None
- **Request Form Data:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `file` (or `image`) | File binary | Yes | QR code image (PNG, JPG, JPEG, WEBP, BMP). Max 5 MB. |

### Success Response - Valid QR with URL (`200 OK`)
```json
{
  "success": true,
  "data": {
    "id": 46,
    "filename": "suspicious_qr.png",
    "file_size": 24580,
    "decoded": true,
    "content": "http://192.168.1.1/login",
    "is_url": true,
    "risk_score": 65,
    "risk_level": "High",
    "recommendation": "Tautan yang dipindai mengandung indikator berisiko tinggi. Jangan dibuka.",
    "url_analysis": {
      "url": "http://192.168.1.1/login",
      "normalized_url": "http://192.168.1.1/login",
      "hostname": "192.168.1.1",
      "risk_score": 65,
      "risk_level": "High",
      "findings": [
        {
          "label": "Host berupa alamat IP",
          "detail": "Phishing kadang menggunakan alamat IP secara langsung sebagai host.",
          "points": 20,
          "status": "Indikator ditemukan"
        },
        {
          "label": "Kata kunci sensitif",
          "detail": "URL mengandung kata login.",
          "points": 10,
          "status": "Indikator ditemukan"
        },
        {
          "label": "Tidak menggunakan HTTPS",
          "detail": "Koneksi HTTP tidak terenkripsi.",
          "points": 5,
          "status": "Indikator ditemukan"
        }
      ]
    },
    "created_at": "2026-11-15T10:16:00+07:00"
  },
  "message": "QR code scanned and decoded successfully"
}
```

### Success Response - Valid QR with Plain Text (`200 OK`)
```json
{
  "success": true,
  "data": {
    "id": 47,
    "filename": "wifi_qr.png",
    "file_size": 18240,
    "decoded": true,
    "content": "WIFI:S:OfficeNetwork;T:WPA;P:SecretPass123;;",
    "is_url": false,
    "risk_score": 0,
    "risk_level": "Low",
    "recommendation": "Konten QR berupa teks non-URL.",
    "url_analysis": null,
    "created_at": "2026-11-15T10:16:15+07:00"
  },
  "message": "QR code scanned successfully (non-URL content)"
}
```

### Error Responses
**No File Uploaded (`400 Bad Request`):**
```json
{
  "success": false,
  "data": null,
  "message": "File gambar QR code tidak ditemukan dalam request."
}
```

**QR Code Not Detected / Unreadable (`400 Bad Request`):**
```json
{
  "success": false,
  "data": null,
  "message": "QR code tidak dapat dideteksi atau gambar tidak terbaca."
}
```

**File Size Exceeds 5MB (`413 Payload Too Large`):**
```json
{
  "success": false,
  "data": null,
  "message": "Ukuran file melebihi batas maksimal 5 MB."
}
```

---

## 4. Email Phishing Analyzer

Analyzes email subject, body, and sender using local heuristics (urgency, credential harvesting, financial fraud, prizes, sender spoofing patterns) and extracts embedded URLs for in-depth threat analysis. Complete email body is never permanently stored for user privacy.

- **HTTP Method:** `POST`
- **Endpoint URL:** `/api/email/analyze`
- **Request Headers:** `Content-Type: application/json`
- **Query Parameters:** None
- **Request Body (JSON):**
```json
{
  "subject": "URGENT: Your account has been suspended! Verify immediately",
  "body": "Dear Customer, We detected unauthorized activity on your banking account. Please verify your password and update your security info within 24 hours at http://secure-banking-alert.com/login or your account will be closed.",
  "sender": "support@bank-security-service.xyz"
}
```

### Request Parameters
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `subject` | string | Yes | Email subject line |
| `body` | string | Yes | Email text content |
| `sender` | string | No | Sender email address (optional, e.g. `service@paypal.com`) |

### Success Response (`200 OK`)
```json
{
  "success": true,
  "data": {
    "id": 48,
    "subject": "URGENT: Your account has been suspended! Verify immediately",
    "sender": "support@bank-security-service.xyz",
    "risk_score": 85,
    "risk_level": "High",
    "recommendation": "Email ini mengandung pola rekayasa sosial dan indikator penipuan berisiko tinggi. Jangan klik tautan atau berikan informasi sensitif.",
    "suspicious_keywords": [
      "urgent",
      "suspended",
      "verify",
      "password",
      "24 hours"
    ],
    "findings": [
      {
        "category": "urgency_threats",
        "label": "Bahasa mendesak dan ancaman",
        "detail": "Ditemukan kata: 'urgent', 'suspended', '24 hours'. Pelaku sering menekan korban agar bertindak terburu-buru.",
        "points": 25,
        "status": "Indikator ditemukan"
      },
      {
        "category": "credential_harvesting",
        "label": "Permintaan kredensial dan kata sandi",
        "detail": "Email meminta verifikasi kata sandi atau data akun sensitif.",
        "points": 30,
        "status": "Indikator ditemukan"
      },
      {
        "category": "sender_suspicion",
        "label": "Domain pengirim mencurigakan",
        "detail": "Pengirim menggunakan domain TLD berisiko tinggi (.xyz) yang mengatasnamakan layanan perbankan.",
        "points": 15,
        "status": "Indikator ditemukan"
      },
      {
        "category": "embedded_urls",
        "label": "Tautan berisiko tinggi terdeteksi",
        "detail": "Tautan di dalam email mengandung indikator phishing berisiko tinggi.",
        "points": 25,
        "status": "Indikator ditemukan"
      }
    ],
    "extracted_urls": [
      "http://secure-banking-alert.com/login"
    ],
    "url_analyses": [
      {
        "url": "http://secure-banking-alert.com/login",
        "hostname": "secure-banking-alert.com",
        "risk_score": 60,
        "risk_level": "High"
      }
    ],
    "created_at": "2026-11-15T10:16:45+07:00",
    "disclaimer": "Analisis ini berbasis heuristik lokal pada teks dan URL. Tidak memverifikasi catatan DNS SPF/DKIM/DMARC."
  },
  "message": "Email analysis completed successfully"
}
```

### Error Responses
**Missing Subject or Body (`400 Bad Request`):**
```json
{
  "success": false,
  "data": null,
  "message": "Subjek dan isi email wajib diisi."
}
```

---

## 5. File Hash Checker

Calculates the SHA-256 cryptographic digest of an uploaded file without executing or extracting it. Compares the hash against a local known-malicious threat signature database. Temporary files are automatically deleted after processing.

- **HTTP Method:** `POST`
- **Endpoint URL:** `/api/file/scan`
- **Request Headers:** `Content-Type: multipart/form-data`
- **Query Parameters:** None
- **Request Form Data:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `file` | File binary | Yes | Uploaded file to inspect. Maximum size 10 MB. |

### Success Response - Known Malicious Hash Match (`200 OK`)
```json
{
  "success": true,
  "data": {
    "id": 49,
    "filename": "invoice_update.exe",
    "file_size": 69632,
    "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    "reputation": "Malicious",
    "risk_score": 100,
    "risk_level": "High",
    "threat_details": {
      "threat_name": "EICAR-Standard-AV-Test-File",
      "description": "Standard antivirus test pattern simulating malware payload",
      "source": "EICAR / PhishGuard Local Threat DB",
      "date_added": "2026-11-13T10:00:00+07:00"
    },
    "recommendation": "File teridentifikasi sebagai ancaman berbahaya dalam database signature. Segera isolasi atau hapus file.",
    "created_at": "2026-11-15T10:17:10+07:00",
    "disclaimer": "Pemeriksaan berdasarkan perbandingan hash SHA-256 lokal tanpa eksekusi file."
  },
  "message": "Malicious signature matched in threat database"
}
```

### Success Response - No Match Found (`200 OK`)
```json
{
  "success": true,
  "data": {
    "id": 50,
    "filename": "clean_document.pdf",
    "file_size": 154200,
    "sha256": "a35d96b1b7...c13e",
    "reputation": "Unknown / Clean in local DB",
    "risk_score": 0,
    "risk_level": "Low",
    "threat_details": null,
    "recommendation": "Hash file tidak cocok dengan signature malware di database lokal. Tetap berhati-hati jika file berasal dari sumber tidak dikenal.",
    "created_at": "2026-11-15T10:17:35+07:00",
    "disclaimer": "Tidak adanya kecocokan pada database lokal bukan jaminan absolut bahwa file aman."
  },
  "message": "File hash calculated. No matching threat found in local signature database."
}
```

### Error Responses
**Missing File (`400 Bad Request`):**
```json
{
  "success": false,
  "data": null,
  "message": "File tidak ditemukan dalam request upload."
}
```

**File Size Exceeds 10MB (`413 Payload Too Large`):**
```json
{
  "success": false,
  "data": null,
  "message": "Ukuran file melebihi batas maksimal 10 MB."
}
```

---

## 6. Threat Watchlist

Manages local threat domain and URL watchlist entries. Matching entries directly elevate risk scores during URL scans.

### 6.1 List Watchlist Entries
- **HTTP Method:** `GET`
- **Endpoint URL:** `/api/watchlist`
- **Query Parameters:**
  - `search` *(optional)*: Filter entries by target, threat category, or description.

#### Success Response (`200 OK`)
```json
{
  "success": true,
  "data": {
    "total": 3,
    "items": [
      {
        "id": 1,
        "target": "phishing-bank-login.com",
        "threat_category": "Credential Harvesting",
        "description": "Known fake banking portal",
        "source": "Security Team Manual",
        "date_added": "2026-11-14T08:00:00+07:00"
      },
      {
        "id": 2,
        "target": "apple-id-verify.top",
        "threat_category": "Phishing",
        "description": "Impersonates Apple ID verification",
        "source": "Threat Intel Feed",
        "date_added": "2026-11-14T09:30:00+07:00"
      }
    ]
  },
  "message": "Watchlist retrieved successfully"
}
```

---

### 6.2 Add Watchlist Entry
- **HTTP Method:** `POST`
- **Endpoint URL:** `/api/watchlist`
- **Request Headers:** `Content-Type: application/json`
- **Request Body (JSON):**
```json
{
  "target": "fake-paypal-login.xyz",
  "threat_category": "Phishing",
  "description": "Deceptive PayPal clone page",
  "source": "Admin Manual Entry"
}
```

#### Request Parameters
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `target` | string | Yes | Hostname, domain, or full URL to flag |
| `threat_category` | string | Yes | Category (e.g. `Phishing`, `Malware`, `Scam`, `Credential Harvesting`) |
| `description` | string | No | Descriptive reason for watchlisting |
| `source` | string | No | Source of intelligence (default: `Manual Entry`) |

#### Success Response (`201 Created`)
```json
{
  "success": true,
  "data": {
    "id": 4,
    "target": "fake-paypal-login.xyz",
    "threat_category": "Phishing",
    "description": "Deceptive PayPal clone page",
    "source": "Admin Manual Entry",
    "date_added": "2026-11-15T10:18:00+07:00"
  },
  "message": "Watchlist entry created successfully"
}
```

#### Error Responses
**Missing Required Fields (`400 Bad Request`):**
```json
{
  "success": false,
  "data": null,
  "message": "Target dan kategori ancaman wajib diisi."
}
```

**Duplicate Entry (`409 Conflict`):**
```json
{
  "success": false,
  "data": null,
  "message": "Target ini sudah terdaftar dalam watchlist."
}
```

---

### 6.3 Delete Watchlist Entry
- **HTTP Method:** `DELETE`
- **Endpoint URL:** `/api/watchlist/<int:id>`
- **Request Headers:** None
- **Query Parameters:** None

#### Success Response (`200 OK`)
```json
{
  "success": true,
  "data": {
    "deleted_id": 4
  },
  "message": "Watchlist entry deleted successfully"
}
```

#### Error Response (`404 Not Found`)
```json
{
  "success": false,
  "data": null,
  "message": "Entry watchlist dengan ID 4 tidak ditemukan."
}
```

---

## 7. Dashboard Analytics

Provides aggregated security metrics and time-series activity data derived strictly from real SQLite database records.

### 7.1 Overall Dashboard Stats
- **HTTP Method:** `GET`
- **Endpoint URL:** `/api/dashboard/stats`
- **Request Headers:** None
- **Query Parameters:** None

#### Success Response (`200 OK`)
```json
{
  "success": true,
  "data": {
    "summary": {
      "total_scans": 52,
      "high_risk_count": 14,
      "medium_risk_count": 8,
      "low_risk_count": 30,
      "watchlist_matches": 6
    },
    "scans_by_type": {
      "url": 30,
      "qr": 10,
      "email": 8,
      "file": 4
    },
    "risk_distribution": [
      { "level": "High", "count": 14, "percentage": 26.9 },
      { "level": "Medium", "count": 8, "percentage": 15.4 },
      { "level": "Low", "count": 30, "percentage": 57.7 }
    ],
    "recent_alerts": [
      {
        "id": 48,
        "scan_type": "email",
        "target": "URGENT: Your account has been suspended! Verify immediately",
        "risk_score": 85,
        "risk_level": "High",
        "created_at": "2026-11-15T10:16:45+07:00"
      }
    ],
    "recent_activities": [
      {
        "id": 50,
        "scan_type": "file",
        "target": "clean_document.pdf",
        "risk_score": 0,
        "risk_level": "Low",
        "created_at": "2026-11-15T10:17:35+07:00"
      },
      {
        "id": 49,
        "scan_type": "file",
        "target": "invoice_update.exe",
        "risk_score": 100,
        "risk_level": "High",
        "created_at": "2026-11-15T10:17:10+07:00"
      }
    ]
  },
  "message": "Dashboard statistics retrieved successfully"
}
```

---

### 7.2 Activity Timeline
- **HTTP Method:** `GET`
- **Endpoint URL:** `/api/dashboard/activity?period=7d`
- **Query Parameters:**
  - `period` *(optional)*: `7d` (default) or `30d`.

#### Success Response (`200 OK`)
```json
{
  "success": true,
  "data": {
    "period": "7d",
    "timeline": [
      { "date": "2026-11-09", "total": 2, "high": 0, "medium": 0, "low": 2 },
      { "date": "2026-11-10", "total": 5, "high": 1, "medium": 1, "low": 3 },
      { "date": "2026-11-11", "total": 8, "high": 2, "medium": 1, "low": 5 },
      { "date": "2026-11-12", "total": 12, "high": 3, "medium": 2, "low": 7 },
      { "date": "2026-11-13", "total": 7, "high": 2, "medium": 1, "low": 4 },
      { "date": "2026-11-14", "total": 10, "high": 4, "medium": 2, "low": 4 },
      { "date": "2026-11-15", "total": 8, "high": 2, "medium": 1, "low": 5 }
    ]
  },
  "message": "Activity timeline retrieved successfully"
}
```

---

## 8. Unified Scan History

Retrieves historical scan records across all four modules (`url`, `qr`, `email`, `file`) with search, filter, and pagination support.

### 8.1 List History Entries
- **HTTP Method:** `GET`
- **Endpoint URL:** `/api/history`
- **Query Parameters:**
| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `type` | string | No | `all` | Filter by scan type: `all`, `url`, `qr`, `email`, `file` |
| `risk` | string | No | `all` | Filter by risk level: `all`, `Low`, `Medium`, `High` |
| `search` | string | No | `""` | Search text in target, hostname, or recommendation |
| `page` | integer | No | `1` | Page number (1-based) |
| `per_page` | integer | No | `10` | Records per page (max 100) |

#### Success Response (`200 OK`)
```json
{
  "success": true,
  "data": {
    "items": [
      {
        "id": 50,
        "scan_type": "file",
        "target": "clean_document.pdf",
        "hostname": "",
        "risk_score": 0,
        "risk_level": "Low",
        "recommendation": "Hash file tidak cocok dengan signature malware di database lokal.",
        "created_at": "2026-11-15T10:17:35+07:00"
      },
      {
        "id": 49,
        "scan_type": "file",
        "target": "invoice_update.exe",
        "hostname": "",
        "risk_score": 100,
        "risk_level": "High",
        "recommendation": "File teridentifikasi sebagai ancaman berbahaya dalam database signature.",
        "created_at": "2026-11-15T10:17:10+07:00"
      }
    ],
    "pagination": {
      "page": 1,
      "per_page": 10,
      "total_items": 52,
      "total_pages": 6,
      "has_next": true,
      "has_prev": false
    }
  },
  "message": "Scan history retrieved successfully"
}
```

---

### 8.2 Get History Detail
- **HTTP Method:** `GET`
- **Endpoint URL:** `/api/history/<int:id>`
- **Request Headers:** None
- **Query Parameters:** None

#### Success Response (`200 OK`)
```json
{
  "success": true,
  "data": {
    "id": 48,
    "scan_type": "email",
    "target": "URGENT: Your account has been suspended! Verify immediately",
    "hostname": "bank-security-service.xyz",
    "risk_score": 85,
    "risk_level": "High",
    "recommendation": "Email ini mengandung pola rekayasa sosial dan indikator penipuan berisiko tinggi.",
    "findings": [
      {
        "label": "Bahasa mendesak dan ancaman",
        "detail": "Ditemukan kata: 'urgent', 'suspended', '24 hours'.",
        "points": 25,
        "status": "Indikator ditemukan"
      }
    ],
    "created_at": "2026-11-15T10:16:45+07:00"
  },
  "message": "Scan record retrieved successfully"
}
```

#### Error Response (`404 Not Found`)
```json
{
  "success": false,
  "data": null,
  "message": "Riwayat pemeriksaan dengan ID 999 tidak ditemukan."
}
```
