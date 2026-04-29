# CN322 WAF — Web Application Firewall

> โครงงานรายวิชา CN322 Network Security  
> สาขาวิชาวิศวกรรมคอมพิวเตอร์ มหาวิทยาลัยธรรมศาสตร์ ภาคเรียนที่ 2/2568

ระบบ Web Application Firewall (WAF) พัฒนาด้วย Python + Flask ทำงานในรูปแบบ **Reverse Proxy** เพื่อตรวจจับและป้องกันการโจมตีประเภท **SQL Injection (SQLi)** และ **Cross-Site Scripting (XSS)**

---

## สมาชิก

| ชื่อ                         | รหัสนักศึกษา |
| ---------------------------- | ------------ |
| นางสาวธนวรรณ ผ่องแผ้ว        | 6610685171   |
| นางสาวเนตรชนก ยินดี          | 6610685221   |
| นายสิรณัฏฐ์ พิมพิจารณ์       | 6610685353   |
| นางสาวอันติมาดา แสงรุ่งเรือง | 6610685387   |

---

## ภาพรวมระบบ

```
Internet ──► NGINX (SSL Termination) ──► WAF Proxy ──► Dummy Web App
                                              │
                                         Admin Dashboard (port 5005)
```

ทุก Request จากภายนอกจะต้องผ่าน 3 ชั้นการป้องกัน (Defense-in-Depth):

1. **NGINX** — SSL Termination, Rate Limiting, L7 Pre-screening
2. **WAF Proxy** — Payload Scanning Engine (SQLi + XSS Detection)
3. **Dummy Web App** — ตรวจสอบ Shared Secret Header ก่อนประมวลผล

---

## คุณสมบัติหลัก

- ตรวจจับ **SQL Injection** ครอบคลุม 13 หมวดรูปแบบการโจมตี (70+ rules)
- ตรวจจับ **XSS** ครอบคลุม Script Tags, Event Handlers, DOM Sinks และ Obfuscation (70+ rules)
- **Recursive Normalization** ถอดรหัสซ้อนหลายชั้น (URL, HTML Entity, Unicode, Base64, Hex) สูงสุด 5 รอบ
- **Weighted Scoring System** — บล็อกเมื่อคะแนนรวม ≥ 15 ลด False Positive ด้วย Natural Language Heuristics
- **Admin Dashboard** — แสดงสถิติการโจมตี, Attack Logs แบบ Real-time, IP Ban Management
- **Async Logging** — บันทึก Log แบบ Non-blocking ไม่กระทบ Latency หลัก

---

## ผลการทดสอบ

| เกณฑ์                        | เป้าหมาย | ผลที่ได้              |
| ---------------------------- | -------- | --------------------- |
| SQLi Detection Rate          | ≥ 85%    | **100%**              |
| XSS Detection Rate           | ≥ 85%    | **100%**              |
| False Positive Rate          | ≤ 5%     | **0.00%** (baseline)  |
| WAF Block Rate (Stress Test) | ≥ 85%    | **97.95%**            |
| Latency p95 (baseline)       | ≤ 500 ms | **24.31 ms**          |
| sqlmap Exploitable           | 0        | **0** (8/8 scenarios) |

---

## System Requirements

### macOS

- macOS 12 (Monterey) ขึ้นไป
- Docker Desktop 4.x ขึ้นไป
- Git 2.x ขึ้นไป

### Windows

- Windows 10 / 11 (64-bit)
- Docker Desktop พร้อม WSL2 Backend
- Git for Windows

---

## การติดตั้งและรันระบบ

### 1. Clone Repository

```bash
git clone https://github.com/6610685387/CN322_WAF.git
cd CN322_WAF
```

### 2. (Optional) Virtual Environment สำหรับ Local Testing

```bash
# macOS / Linux
python3 -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
venv\Scripts\activate
```

### 3. ติดตั้ง Dependencies

```bash
pip install -r requirements.txt
```

### 4. รันระบบด้วย Docker Compose

```bash
docker-compose up --build
```

ระบบจะเริ่มทำงานตามลำดับ: `dummy_web` → `waf_proxy` → `admin_panel` → `nginx`

---

## Endpoints

### Online Demo (Live)

- **WAF Entry Point:** `https://waf-cn322.duckdns.org/` (หน้าเว็บหลักที่ผ่านการป้องกัน)
- **Admin Dashboard:** `https://waf-cn322.duckdns.org:5005/admin` (หน้าเว็บแอดมินแดชบอร์ด)

### Local Environment

| Service         | URL                           | หน้าที่                  |
| --------------- | ----------------------------- | ------------------------ |
| WAF             | `https://localhost:5000/`     | หน้าเว็บหลักผ่าน WAF     |
| Web Application         | `https://localhost:5001/`     | หน้าเว็บหลักผ่าน         |
| Admin Dashboard | `http://localhost:5005/admin` | ดู Logs และจัดการ IP Ban |

---

## โครงสร้างโปรเจกต์

```
CN322_WAF/
├── docker-compose.yml
├── nginx/
│   └── nginx.conf
├── waf_proxy/
│   ├── waf.py                  # Core Request Handler
│   ├── admin_dashboard.py      # Admin UI & REST API
│   ├── database_manager.py     # PostgreSQL + IP Ban Cache
│   └── detectors/
│       ├── __init__.py         # Scanning Orchestrator
│       ├── normalizer.py       # Recursive Normalization Engine
│       ├── sqli_detector.py    # SQL Injection Detection Rules
│       └── xss_detector.py     # XSS Detection Rules
├── dummy-web/
│   ├── target_app.py           # Vulnerable Target App (for testing)
│   └── templates/
└── tests/
    └── security/pytest/
        ├── test_1_sqli.py
        ├── test_2_xss.py
        ├── test_3_false_positive.py
        └── test_4_fp_comprehensive.py
```

---

## การรัน Security Tests

```bash
# รันทุก test
pytest tests/security/pytest/ -v

# รัน test เฉพาะหมวด
pytest tests/security/pytest/test_1_sqli.py -v
pytest tests/security/pytest/test_2_xss.py -v
pytest tests/security/pytest/test_3_false_positive.py -v
pytest tests/security/pytest/test_4_fp_comprehensive.py -v
```

---

## เทคโนโลยีที่ใช้

| Component        | Technology                    |
| ---------------- | ----------------------------- |
| WAF Engine       | Python 3, Flask, Gunicorn     |
| Reverse Proxy    | NGINX                         |
| Database         | PostgreSQL + SQLAlchemy       |
| Containerization | Docker, Docker Compose        |
| Testing          | pytest, sqlmap, GoTestWAF, k6 |

---

## License

โครงงานนี้จัดทำขึ้นเพื่อวัตถุประสงค์ทางการศึกษาเท่านั้น  
ภาควิชาวิศวกรรมคอมพิวเตอร์ มหาวิทยาลัยธรรมศาสตร์ © 2568
