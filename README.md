<!-- LANGUAGE SWITCHER -->
<div align="center">

**🌐 Choose your language / Pilih bahasa:**

[![🇬🇧 English](https://img.shields.io/badge/🇬🇧-English-4A90D9?style=for-the-badge)](#-documentation--english-)
[![🇮🇩 Indonesia](https://img.shields.io/badge/🇮🇩-Indonesia-CC0001?style=for-the-badge)](#-dokumentasi--bahasa-indonesia-)

</div>

---

<!-- ENGLISH VERSION -->
<a id="-documentation--english-"></a>

<div align="center">

```
         ██╗  ██╗ ██████╗ ██████╗     ██████╗ ██╗   ██╗██████╗  █████╗ ███████╗███████╗
         ██║  ██║██╔═══██╗╚════██╗    ██╔══██╗╚██╗ ██╔╝██╔══██╗██╔══██╗██╔════╝██╔════╝
         ███████║██║   ██║ █████╔╝    ██████╔╝ ╚████╔╝ ██████╔╝███████║███████╗███████╗
         ╚════██║██║   ██║ ╚═══██╗    ██╔══██╗  ╚██╔╝  ██╔═══╝ ██╔══██║╚════██║╚════██║
              ██║╚██████╔╝██████╔╝    ██████╔╝   ██║   ██║     ██║  ██║███████║███████║
              ╚═╝ ╚═════╝ ╚═════╝     ╚═════╝    ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝
                                                                                          
                        ╔══════════════════════════════════╗
                        ║  HTTP 403 Forbidden Bypass Tester 
                        ║  --------------•---------------  
                        ╚══════════════════════════════════╝
```

[![Python](https://img.shields.io/badge/Python-100%25-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Lisensi: GPL v3](https://img.shields.io/badge/Lisensi-GPLv3-blue?style=flat-square)](LICENSE)
[![Performa](https://img.shields.io/badge/Performa-Cepat-brightgreen?style=flat-square)]()
[![Build](https://img.shields.io/badge/Build-Ringan-yellowgreen?style=flat-square)]()
[![PRs](https://img.shields.io/badge/PRs-Diterima-orange?style=flat-square)](CONTRIBUTING.md)
[![Etika](https://img.shields.io/badge/Gunakan-Secara_Etis-red?style=flat-square&logo=hackthebox&logoColor=white)]()

*A modular HTTP 403 bypass testing toolkit for authorized penetration testers and bug bounty hunters.*

</div>

---

> [!WARNING]
> **This tool must only be used on systems you have explicit written permission to test. Unauthorized use is illegal and can be prosecuted.**

---

## ⚡ One-Line Install

```bash
git clone https://github.com/yourusername/bypass-tester && cd bypass-tester && pip install -r requirements.txt
```

---

## 📁 Project Structure

```
bypass-tester/
├── bypass_tester_main.py       ← Main entry point
├── requirements.txt
├── README.md
│
├── payloads/
│   ├── __init__.py
│   ├── header_payloads.py      ← IP spoof, auth bypass, content-type, misc headers
│   ├── path_payloads.py        ← Path traversal, extension bypass
│   └── all_payloads.py         ← Method, param pollution, query, JSON injection,
│                                  HTTP smuggling, host header, rate limit,
│                                  cache poisoning, CORS, double encoding
│
└── modules/
    ├── __init__.py
    ├── query_injection_test.py  ← query_injection_test()
    ├── host_header_test.py      ← host_header_test()
    ├── rate_limit_test.py       ← rate_limit_test()
    └── json_fuzz_test.py        ← json_fuzz_test()
```

---

## 🚀 Usage

### Run all modules (default target)
```bash
python bypass_tester_main.py
```

### Custom target
```bash
python bypass_tester_main.py https://target.example.com/api/endpoint
```

### Select specific modules
```bash
python bypass_tester_main.py https://target.com/api -m headers paths methods
python bypass_tester_main.py https://target.com/api -m cors smuggling host
python bypass_tester_main.py https://target.com/api -m ratelimit --burst 20
python bypass_tester_main.py https://target.com/api -m json --verbose
```

### Save output to JSON
```bash
python bypass_tester_main.py https://target.com/api -o results.json
```

### All options
```bash
python bypass_tester_main.py --help
```

---

## 📦 Modules & Payloads

| Flag               | Description                                              |
|--------------------|----------------------------------------------------------|
| `headers`          | IP spoofing, auth bypass, content-type confusion         |
| `paths`            | Path traversal, URL encoding, extension bypass           |
| `methods`          | HTTP verb confusion + method override headers            |
| `params`           | Parameter pollution, duplicate params, type tricks       |
| `query`            | Query manipulation, double encoding, SQLi-ish payloads   |
| `json`             | JSON type confusion, prototype pollution, malformed body |
| `smuggling`        | CL.TE / TE.CL / TE.TE HTTP request smuggling            |
| `host`             | Host header injection, SSRF via Host, CRLF injection     |
| `ratelimit`        | IP rotation, path variation, concurrent burst, drip      |
| `cache`            | Cache poisoning headers + cache buster params            |
| `cors`             | CORS misconfig, credential reflection, preflight abuse   |
| `encoding`         | Double/triple encoding, unicode normalization bypasses   |

---

## 🖥 CLI Flags

| Flag              | Default    | Description                                   |
|-------------------|------------|-----------------------------------------------|
| `url`             | *(built-in)*| Target URL                                   |
| `-m / --modules`  | `all`      | Select modules to run                         |
| `-o / --output`   | `None`     | JSON file path for saving the report          |
| `-t / --timeout`  | `7`        | Per-request timeout (seconds)                 |
| `-b / --burst`    | `15`       | Number of concurrent requests (rate limiting) |
| `-v / --verbose`  | `False`    | Show extra detail per request                 |

---

## 📊 Output Format

Each request produces:
```
[STATUS_CODE] N bytes  ← summary line
⚠ / ✅ / ❌           ← finding flag
```

The JSON report (`-o`) contains:

| Field       | Description                                         |
|-------------|-----------------------------------------------------|
| `target`    | Tested URL                                          |
| `timestamp` | UTC timestamp                                       |
| `summary`   | Total requests & interesting hits per module        |
| `findings`  | Findings with severity label (`HIGH` / `MEDIUM`)    |
| `results`   | All raw data per module                             |

---

## 🔬 Example Output

```
🎯 Target  : https://api.example.com/v1/data
⏱  Timeout : 7s
📦 Modules : all

══════════════════════════════════════════════════════════════
  TEST: HEADER BYPASS
══════════════════════════════════════════════════════════════

[IP Spoof]
  X-Forwarded-For: 127.0.0.1                       -> [200] 1337 bytes ✅ BYPASS
  X-Real-IP: 127.0.0.1                             -> [403]   42 bytes ❌
  ...

[CORS EXPLOITATION]
  PRE [200] 0 bytes | ACT [200] 1337 bytes | ACAO=https://attacker.com ⚠ CORS REFLECTED

══════════════════════════════════════════════════════════════
  SUMMARY
══════════════════════════════════════════════════════════════
  Total Requests  : 284
  Interesting     : 7
  High Severity   : 2
  Medium Severity : 5
```

---

## ⚖️ Legal & Ethics

This tool is built for **authorized penetration testing**, bug bounty programs, and cybersecurity education. Always:

1. ✅ Obtain **written permission** from the system owner before testing
2. 📄 Document all testing activity thoroughly
3. 🔒 Report findings via **responsible disclosure**
4. 🚫 Never misuse or weaponize discovered vulnerabilities

---

## 🤝 Contributing

Pull requests are welcome.

---

<div align="center">

----- &nbsp;·&nbsp;

[![Back to Top](https://img.shields.io/badge/↑-Back_to_Top-grey?style=flat-square)](#-documentation--english-)

</div>

---
---

<!-- INDONESIAN VERSION -->
<a id="-dokumentasi--bahasa-indonesia-"></a>

<div align="center">

```
         ██╗  ██╗ ██████╗ ██████╗     ██████╗ ██╗   ██╗██████╗  █████╗ ███████╗███████╗
         ██║  ██║██╔═══██╗╚════██╗    ██╔══██╗╚██╗ ██╔╝██╔══██╗██╔══██╗██╔════╝██╔════╝
         ███████║██║   ██║ █████╔╝    ██████╔╝ ╚████╔╝ ██████╔╝███████║███████╗███████╗
         ╚════██║██║   ██║ ╚═══██╗    ██╔══██╗  ╚██╔╝  ██╔═══╝ ██╔══██║╚════██║╚════██║
              ██║╚██████╔╝██████╔╝    ██████╔╝   ██║   ██║     ██║  ██║███████║███████║
              ╚═╝ ╚═════╝ ╚═════╝     ╚═════╝    ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝
                                                                                          
                        ╔══════════════════════════════════╗
                        ║  HTTP 403 Forbidden Bypass Tester 
                        ║  --------------•-----------------  
                        ╚══════════════════════════════════╝
```

[![Python](https://img.shields.io/badge/Python-100%25-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Lisensi: GPL v3](https://img.shields.io/badge/Lisensi-GPLv3-blue?style=flat-square)](LICENSE)
[![Performa](https://img.shields.io/badge/Performa-Cepat-brightgreen?style=flat-square)]()
[![Build](https://img.shields.io/badge/Build-Ringan-yellowgreen?style=flat-square)]()
[![PRs](https://img.shields.io/badge/PRs-Diterima-orange?style=flat-square)](CONTRIBUTING.md)
[![Etika](https://img.shields.io/badge/Gunakan-Secara_Etis-red?style=flat-square&logo=hackthebox&logoColor=white)]()

*Toolkit pengujian bypass HTTP 403 yang modular untuk penetration tester dan bug bounty hunter terotorisasi.*

</div>

---

> [!WARNING]
> **Tool ini hanya boleh digunakan pada sistem yang Anda miliki izin tertulis untuk diuji. Penggunaan tanpa izin adalah tindakan ilegal dan dapat dipidanakan.**

---

## ⚡ Instalasi Satu Baris

```bash
git clone https://github.com/yourusername/bypass-tester && cd bypass-tester && pip install -r requirements.txt
```

---

## 📁 Struktur Proyek

```
bypass-tester/
├── bypass_tester_main.py       ← Entry point utama
├── requirements.txt
├── README.md
│
├── payloads/
│   ├── __init__.py
│   ├── header_payloads.py      ← IP spoof, auth bypass, content-type, misc headers
│   ├── path_payloads.py        ← Path traversal, extension bypass
│   └── all_payloads.py         ← Method, param pollution, query, JSON injection,
│                                  HTTP smuggling, host header, rate limit,
│                                  cache poisoning, CORS, double encoding
│
└── modules/
    ├── __init__.py
    ├── query_injection_test.py  ← query_injection_test()
    ├── host_header_test.py      ← host_header_test()
    ├── rate_limit_test.py       ← rate_limit_test()
    └── json_fuzz_test.py        ← json_fuzz_test()
```

---

## 🚀 Penggunaan

### Jalankan semua modul (target default)
```bash
python bypass_tester_main.py
```

### Target kustom
```bash
python bypass_tester_main.py https://target.example.com/api/endpoint
```

### Pilih modul tertentu
```bash
python bypass_tester_main.py https://target.com/api -m headers paths methods
python bypass_tester_main.py https://target.com/api -m cors smuggling host
python bypass_tester_main.py https://target.com/api -m ratelimit --burst 20
python bypass_tester_main.py https://target.com/api -m json --verbose
```

### Simpan output ke JSON
```bash
python bypass_tester_main.py https://target.com/api -o hasil_test.json
```

### Semua opsi
```bash
python bypass_tester_main.py --help
```

---

## 📦 Modul & Payload

| Flag               | Fungsi                                                       |
|--------------------|--------------------------------------------------------------|
| `headers`          | IP spoofing, auth bypass, content-type confusion             |
| `paths`            | Path traversal, URL encoding, extension bypass               |
| `methods`          | HTTP verb confusion + method override headers                |
| `params`           | Parameter pollution, duplicate params, type tricks           |
| `query`            | Query manipulation, double encoding, payload mirip SQLi      |
| `json`             | JSON type confusion, prototype pollution, malformed body     |
| `smuggling`        | CL.TE / TE.CL / TE.TE HTTP request smuggling                |
| `host`             | Host header injection, SSRF via Host, CRLF injection         |
| `ratelimit`        | IP rotation, path variation, concurrent burst, drip          |
| `cache`            | Cache poisoning headers + parameter cache buster             |
| `cors`             | CORS misconfig, credential reflection, preflight abuse       |
| `encoding`         | Double/triple encoding, bypass normalisasi unicode           |

---

## 🖥 Flag CLI

| Flag              | Default    | Keterangan                                    |
|-------------------|------------|-----------------------------------------------|
| `url`             | *(bawaan)* | URL target                                    |
| `-m / --modules`  | `all`      | Pilih modul yang dijalankan                   |
| `-o / --output`   | `None`     | Path file JSON untuk menyimpan laporan        |
| `-t / --timeout`  | `7`        | Timeout per request (detik)                   |
| `-b / --burst`    | `15`       | Jumlah concurrent request (rate limiting)     |
| `-v / --verbose`  | `False`    | Tampilkan detail ekstra per request           |

---

## 📊 Format Output

Setiap request menghasilkan:
```
[STATUS_CODE] N bytes  ← ringkasan
⚠ / ✅ / ❌           ← flag temuan
```

Laporan JSON (`-o`) berisi:

| Field       | Deskripsi                                             |
|-------------|-------------------------------------------------------|
| `target`    | URL yang diuji                                        |
| `timestamp` | Waktu UTC                                             |
| `summary`   | Jumlah request & temuan menarik per modul             |
| `findings`  | Temuan beserta severity (`HIGH` / `MEDIUM`)           |
| `results`   | Semua raw data per modul                              |

---

## 🔬 Contoh Output

```
🎯 Target  : https://api.example.com/v1/data
⏱  Timeout : 7s
📦 Modules : all

══════════════════════════════════════════════════════════════
  TEST: HEADER BYPASS
══════════════════════════════════════════════════════════════

[IP Spoof]
  X-Forwarded-For: 127.0.0.1                       -> [200] 1337 bytes ✅ BYPASS
  X-Real-IP: 127.0.0.1                             -> [403]   42 bytes ❌
  ...

[CORS EXPLOITATION]
  PRE [200] 0 bytes | ACT [200] 1337 bytes | ACAO=https://attacker.com ⚠ CORS REFLECTED

══════════════════════════════════════════════════════════════
  RINGKASAN
══════════════════════════════════════════════════════════════
  Total Request   : 284
  Menarik         : 7
  High Severity   : 2
  Medium Severity : 5
```

---

## ⚖️ Legal & Etika

Tool ini dibuat untuk keperluan **authorized penetration testing**, bug bounty, dan edukasi keamanan siber. Pastikan selalu:

1. ✅ Memiliki **izin tertulis** dari pemilik sistem sebelum melakukan pengujian
2. 📄 Mendokumentasikan seluruh aktivitas pengujian dengan lengkap
3. 🔒 Melaporkan temuan secara **responsible disclosure**
4. 🚫 Tidak menyalahgunakan atau mempersenjatai hasil temuan

---

## 🤝 Kontribusi

Silahkan, Open source 100%
---

<div align="center">

----&nbsp;·&nbsp;

[![Kembali ke Atas](https://img.shields.io/badge/↑-Kembali_ke_Atas-grey?style=flat-square)](#-dokumentasi--bahasa-indonesia-)

</div>
