"""
WAF False Positive Evaluation
==============================
FIX v2:
  - ปรับ assertion threshold → FP ≤ 5% (จากเดิม 15%)
  - เพิ่ม edge cases ที่เคยเป็น FP: "SELECT * FROM documentation"
  - เพิ่ม edge cases URL, CSS hex color ที่ควรผ่าน
  - แก้ไขให้ใช้ config จาก environment (WAF_BASE)
"""

import requests
import json
import time
import urllib3
import os
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

WAF_BASE = os.environ.get("WAF_BASE", "https://localhost")
TIMEOUT = 5
SLEEP_MS = 0.15

# =============================================
# False Positive Test Cases
# (text, description, endpoint_template)
# =============================================
FP_CASES = [
    # ── SQL keywords ในประโยคภาษาอังกฤษธรรมดา ────────────────────────────────
    ("WHERE is the gym?", "ถามทิศทาง - WHERE", "/search?q={}"),
    ("Can I SELECT this item please", "คำขอ - SELECT", "/search?q={}"),
    ("UPDATE me on the latest news", "อัพเดต - UPDATE", "/search?q={}"),
    ("DELETE this account for me", "ลบบัญชี - DELETE", "/search?q={}"),
    ("ORDER BY name or price", "เรียงลำดับ - ORDER BY", "/search?q={}"),
    ("INSERT a new product into the list", "แทรก - INSERT", "/search?q={}"),
    ("DROP me a message anytime", "ส่งข้อความ - DROP", "/search?q={}"),
    ("OR is it available in red?", "คำถาม - OR", "/search?q={}"),
    ("AND I want the blue one too", "เพิ่มเติม - AND", "/search?q={}"),
    ("FROM the collection select one", "จาก collection - FROM", "/search?q={}"),
    ("HAVING a great day today", "การทักทาย - HAVING", "/search?q={}"),
    ("UNION members meeting at 9am", "การประชุม - UNION", "/search?q={}"),
    ("GROUP BY interest or department", "จัดกลุ่ม - GROUP BY", "/search?q={}"),
    ("I want to JOIN the club", "สมาชิก - JOIN", "/search?q={}"),
    # ── FIX: SELECT * FROM patterns ที่เคยเป็น FP ────────────────────────────
    (
        "SELECT * FROM documentation",
        "SELECT * FROM ในเอกสาร tech",
        "/search?q={}",
    ),  # FIX: เคย FP
    (
        "SQL SELECT FROM WHERE tutorial",
        "SQL tutorial keyword",
        "/search?q={}",
    ),  # FIX: เคย FP
    ("how to use SELECT FROM in SQL", "SQL tutorial คำถาม", "/search?q={}"),
    # ── ภาษาไทย ──────────────────────────────────────────────────────────────
    ("ฉันอยากให้อัปเดตข้อมูลด้วย", "ภาษาไทย - อัปเดต", "/search?q={}"),
    ("ลบออเดอร์เก่าออกให้หน่อย", "ภาษาไทย - ลบ", "/search?q={}"),
    ("เลือกสินค้าที่ดีที่สุดให้หน่อย", "ภาษาไทย - เลือก", "/search?q={}"),
    # ── HTML-like แต่ปลอดภัย ─────────────────────────────────────────────────
    ("score > 90 and < 100", "เปรียบเทียบตัวเลข", "/search?q={}"),
    ("I love you <3 so much", "หัวใจ <3", "/search?q={}"),
    ("file.txt <-> database sync", "สัญลักษณ์ arrow", "/search?q={}"),
    ("ratio 1:2 or 3:4", "อัตราส่วน", "/search?q={}"),
    ("2+2=4 and 3*3=9", "สูตรคณิตศาสตร์", "/search?q={}"),
    ("Visit us at http://localhost:80/", "URL ธรรมดา", "/search?q={}"),
    # ── FIX: CSS Hex color ที่เดิมอาจโดน 0x pattern ─────────────────────────
    ("CSS color #FF5733 for the button", "CSS hex color #FF5733", "/search?q={}"),
    ("background: #1a2b3c in dark mode", "CSS hex #1a2b3c", "/search?q={}"),
    # ── Username / Login ─────────────────────────────────────────────────────
    ("alice", "ชื่อ username ปกติ", "/login?username={}"),
    ("user_name_123", "Username underscore", "/login?username={}"),
    ("first.last@email.com", "Email format", "/login?username={}"),
    ("my password is secure", "ข้อความรหัสผ่าน", "/login?username={}"),
    # ── Special chars ทั่วไป ─────────────────────────────────────────────────
    ("C++ programming language", "C++ in search", "/search?q={}"),
    ("price: $100 or less", "ราคาสินค้า", "/search?q={}"),
    ("50% off sale", "เปอร์เซ็นต์", "/search?q={}"),
    ("rock & roll music", "& ในชื่อเพลง", "/search?q={}"),
    ("Tom's favorite book", "apostrophe ปกติ", "/search?q={}"),
    ('He said "Hello World"', "double quote ปกติ", "/search?q={}"),
    # ── Security / Tech keywords ที่ปลอดภัย ──────────────────────────────────
    ("script writing tips", "script ในบริบท writing", "/search?q={}"),
    ("shell script tutorial", "shell script tutorial", "/search?q={}"),
    ("CSS selector tutorial", "CSS selector", "/search?q={}"),
    ("how to select all in excel", "excel select all", "/search?q={}"),
    ("Python function() basics", "function() ใน Python context", "/search?q={}"),
    ("benchmark results for API", "benchmark ≠ BENCHMARK()", "/search?q={}"),
]


def run_test(url):
    try:
        start = time.time()
        r = requests.get(url, verify=False, timeout=TIMEOUT, allow_redirects=False)
        latency_ms = (time.time() - start) * 1000
        return {
            "status": r.status_code,
            "blocked": r.status_code == 403,
            "latency_ms": round(latency_ms, 2),
            "ok": True,
        }
    except Exception:
        return {"status": "ERR", "blocked": None, "latency_ms": 0, "ok": False}


def test_false_positive(result_writer):
    print("=" * 72)
    print("  WAF False Positive Evaluation")
    print(f"  Target: {WAF_BASE}")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("  ทุก request ควร → HTTP 200 (ไม่ถูกบล็อก)")
    print("=" * 72)

    results = []
    tn = fp = err = 0

    for text, desc, endpoint_tpl in FP_CASES:
        url = WAF_BASE + endpoint_tpl.format(requests.utils.quote(text))
        result = run_test(url)
        time.sleep(SLEEP_MS)

        if not result["ok"]:
            err += 1
            icon, outcome = "💥", "ERR"
        elif result["blocked"]:
            fp += 1
            icon, outcome = "⚠️ ", "FP"
        else:
            tn += 1
            icon, outcome = "✅", "TN"

        print(
            f"  {icon} [{outcome}] HTTP {result['status']} | {result['latency_ms']:>7.1f}ms | {desc}"
        )
        print(f"       Input: {text[:65]}")

        results.append(
            {
                "description": desc,
                "input": text,
                "endpoint": endpoint_tpl,
                "outcome": outcome,
                "http_status": result["status"],
                "blocked": result["blocked"],
                "latency_ms": result["latency_ms"],
            }
        )

    total = tn + fp
    fp_rate = (fp / total * 100) if total > 0 else 0

    print("\n" + "=" * 72)
    print("  FALSE POSITIVE SUMMARY")
    print("=" * 72)
    print(f"  Total Benign Tests  : {total}")
    print(f"  ✅ Correctly Allowed : {tn}  (True Negative)")
    print(f"  ⚠️  Wrongly Blocked  : {fp}  (False Positive)")
    print(f"  💥 Errors           : {err}")
    print(f"  False Positive Rate : {fp_rate:.1f}%")

    if fp > 0:
        print(f"\n  ⚠️  Cases ที่โดนบล็อกผิด:")
        for r in results:
            if r["outcome"] == "FP":
                print(
                    f"     → [{r['http_status']}] {r['description']}: {r['input'][:60]}"
                )
    print("=" * 72)

    output = {
        "test_info": {
            "timestamp": datetime.now().isoformat(),
            "target": WAF_BASE,
            "test_type": "FalsePositive",
        },
        "metrics": {
            "false_positive_rate_pct": round(fp_rate, 2),
            "TN": tn,
            "FP": fp,
            "errors": err,
        },
        "results": results,
    }
    result_writer("fp_results", results)

    assert err == 0, f"Connection errors: {err} — WAF ไม่พร้อมใช้งาน"
    assert fp_rate <= 5.0, (  # FIX: เข้มขึ้นจาก 15% → 5%
        f"False Positive Rate {fp_rate:.1f}% > 5% "
        f"(FP={fp}/{total}) — WAF บล็อก benign traffic มากเกินไป\n"
        f"Cases ที่โดนบล็อกผิด: {[r['description'] for r in results if r['outcome']=='FP']}"
    )


if __name__ == "__main__":
    test_false_positive(lambda name, data: None)
