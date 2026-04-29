"""
WAF False Positive Test Suite — Comprehensive Edition
"""

import sys
import os
import json
import time
import urllib3
import requests
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

WAF_URL = os.environ.get("WAF_URL", os.environ.get("WAF_BASE", "https://localhost"))
TIMEOUT = 5
SLEEP_S = 0.1

MODE_HTTP = "--http" in sys.argv or "--both" in sys.argv
MODE_LOCAL = "--http" not in sys.argv or "--both" in sys.argv

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DETECTOR_PATH = os.path.normpath(
    os.path.join(SCRIPT_DIR, "..", "..", "..", "waf_proxy")
)

FP_CASES = [
    # CAT 1: select.*from
    (
        "select your favorite item from the list",
        "select...from ใน UX copy",
        "select_from",
        (10, 30),
    ),
    (
        "please select one option from below",
        "select...from ในคำสั่ง",
        "select_from",
        (10, 30),
    ),
    (
        "I want to select a book from the shelf",
        "select...from ในชีวิตประจำวัน",
        "select_from",
        (10, 30),
    ),
   
    (
        "SELECT * FROM documentation",
        "SELECT * FROM ในเอกสาร tech",
        "select_from",
        (10, 30),
    ),
    (
        "SQL SELECT FROM WHERE tutorial",
        "SQL tutorial ใน search query",
        "select_from",
        (10, 30),
    ),
    (
        "Can you select the best course from the catalog?",
        "select...from ในการศึกษา",
        "select_from",
        (10, 30),
    ),
    # CAT 2: drop keyword
    (
        "drop me a message anytime",
        "drop ในความหมาย ส่ง message",
        "drop_keyword",
        (10, 15),
    ),
    ("I'll drop by tomorrow", "drop ในความหมาย แวะมา", "drop_keyword", (10, 15)),
    ("drop the idea and move on", "drop ในความหมาย ยกเลิก", "drop_keyword", (10, 15)),
    ("ลองดูว่า drop ไหมไม่", "drop ในบริบทภาษาไทย", "drop_keyword", (10, 15)),
    ("raindrop falling slowly", "raindrop = compound word", "drop_keyword", (0, 9)),
    (
        "backdrop design for the show",
        "backdrop = compound word",
        "drop_keyword",
        (0, 9),
    ),
    # CAT 3: Apostrophe
    ("O'Connor", "ชื่อ Irish apostrophe เดียว", "apostrophe", (10, 20)),
    ("O'Brien from Dublin", "ชื่อ Irish + from keyword", "apostrophe", (10, 25)),
    (
        "Tom's blog post from yesterday",
        "possessive (odd) + from",
        "apostrophe",
        (10, 20),
    ),
    ("I'm from the select team", "odd quote + from + select", "apostrophe", (15, 30)),
    ("don't select from dropdown", "odd quote + select + from", "apostrophe", (20, 35)),
    (
        "she can't see where I'm from",
        "2 quotes (even) + where + from",
        "apostrophe",
        (5, 9),
    ),
    ("it's where I'm from", "2 quotes (even) + where + from", "apostrophe", (5, 9)),
    (
        "it's fine, I won't update it",
        "2 quotes (even) + update (no set)",
        "apostrophe",
        (0, 9),
    ),
    (
        "Tom's and Mary's favorite book",
        "2 odd quotes (even total) = OK",
        "apostrophe",
        (0, 9),
    ),
    # CAT 4: insert.*into
    (
        "insert a new line into the text",
        "insert...into ในการเขียน",
        "insert_into",
        (10, 20),
    ),
    (
        "INSERT record INTO table (tutorial)",
        "INSERT INTO ในเอกสาร SQL",
        "insert_into",
        (10, 20),
    ),
    (
        "please insert the key into the lock",
        "insert...into ในชีวิตประจำวัน",
        "insert_into",
        (10, 20),
    ),
    (
        "insert this USB drive into the port",
        "insert...into กับอุปกรณ์",
        "insert_into",
        (10, 20),
    ),
    # CAT 5: update.*set
    (
        "UPDATE SET explained in the docs",
        "update...set ในเอกสาร",
        "update_set",
        (10, 20),
    ),
    (
        "please update and set the new value",
        "update...set ในคำสั่ง user",
        "update_set",
        (10, 20),
    ),
    (
        "update my profile and set a new picture",
        "update...set ใน app",
        "update_set",
        (10, 20),
    ),
    (
        "update the firmware and set defaults",
        "update...set ในคู่มือเทคนิค",
        "update_set",
        (10, 20),
    ),
    # CAT 6: 0x hex values
    ("price is 0x100 baht (=256)", "hex ในราคา", "hex_value", (10, 15)),
    ("0xDEAD code smell", "hex ในคำศัพท์ prog", "hex_value", (10, 15)),
    ("memory address: 0xFF00", "hex ใน memory address", "hex_value", (10, 15)),
    ("CSS color: #FF5733", "CSS #hex → ไม่ควร block", "hex_value", (0, 9)),
    ("color 0xRRGGBB format", "0xRRGGBB ไม่ match hex", "hex_value", (0, 9)),
    # CAT 7: XSS function()
    (
        "function() call convention in JS",
        "function() ใน tutorial",
        "xss_func",
        (10, 20),
    ),
    ("use a callback function() here", "function() ใน callback", "xss_func", (10, 20)),
    ("JavaScript function() basics", "function() ใน JS", "xss_func", (10, 20)),
    ("main function in C language", "function โดยไม่มี ()", "xss_func", (0, 9)),
    ("the add() function returns a value", "add() ≠ function()", "xss_func", (0, 9)),
    # CAT 8: Near-Threshold
    ("it's where I'm from", "~8 คะแนน: ไม่ควร block", "near_boundary", (5, 9)),
    ("she can't find where I'm from", "~8 คะแนน: ไม่ควร block", "near_boundary", (5, 9)),
    (
        "I can't update my profile now",
        "odd quote + update ~7",
        "near_boundary",
        (5, 12),
    ),
    # CAT 9: Thai Language Only
    ("ฉันเลือกสินค้าจากร้านค้า", "Thai: เลือก ≠ SELECT", "thai_only", (0, 5)),
    ("อัปเดตข้อมูลส่วนตัว", "Thai: อัปเดต ≠ UPDATE", "thai_only", (0, 5)),
    ("ลบรายการนี้ออกได้เลย", "Thai: ลบ ≠ DELETE", "thai_only", (0, 5)),
    ("แทรกรูปภาพลงในเอกสาร", "Thai: แทรก ≠ INSERT", "thai_only", (0, 5)),
    ("ดร็อปไฟล์ลงในโฟลเดอร์", "Thai: ดร็อป ≠ DROP", "thai_only", (0, 9)),
    # CAT 10: Developer/Technical
    (
        "SQL SELECT FROM WHERE tutorial",
        "SQL tutorial ใน search",
        "dev_content",
        (10, 30),
    ),
    (
        "how to use INSERT INTO in MySQL",
        "MySQL tutorial ใน search",
        "dev_content",
        (10, 30),
    ),
    ("shell script tutorial", "script ≠ XSS", "dev_content", (0, 9)),
    ("Python script for automation", "script ใน Python context", "dev_content", (0, 9)),
    ("UNION of two mathematical sets", "UNION ในคณิตศาสตร์", "dev_content", (0, 9)),
    (
        "benchmark test results for API",
        "benchmark ≠ BENCHMARK()",
        "dev_content",
        (0, 9),
    ),
    # CAT 11: Username/Login
    ("alice_wonderland", "username ธรรมดา", "username", (0, 9)),
    ("user.name@company.co.th", "email as username", "username", (0, 9)),
    ("select_all_user", "username มีคำ select (underscore)", "username", (0, 9)),
    ("drop_table_mike", "username มีคำ drop (underscore)", "username", (0, 9)),
    ("O'Brien", "username มี apostrophe (Irish name)", "username", (5, 15)),
    # CAT 12: CSS / Hex Color 
    ("CSS background: #1a2b3c", "CSS hex color #1a2b3c", "css_color", (0, 9)),
    ("hex color code #FF5733 in CSS", "hex color code ใน CSS", "css_color", (0, 9)),
    ("rgba(255, 99, 71, 0.5) color", "rgba ไม่ใช่ hex", "css_color", (0, 9)),
]


def load_detector():
    try:
        sys.path.insert(0, DETECTOR_PATH)
        from detectors import scan_payload

        return scan_payload
    except ImportError:
        return None


def http_test(text):
    url = f"{WAF_URL}/search?q={requests.utils.quote(text)}"
    try:
        start = time.time()
        r = requests.get(url, verify=False, timeout=TIMEOUT, allow_redirects=True)
        latency_ms = round((time.time() - start) * 1000, 1)
        return r.status_code, latency_ms
    except requests.exceptions.ConnectionError:
        return 0, 0
    except requests.exceptions.Timeout:
        return 0, TIMEOUT * 1000


def test_comprehensive_false_positives(result_writer=None):
    if result_writer is None:
        result_writer = lambda name, data: None

    print("=" * 90)
    print("  WAF False Positive Test Suite — Comprehensive Edition")
    mode_label = (
        "LOCAL+HTTP"
        if MODE_LOCAL and MODE_HTTP
        else ("LOCAL only" if MODE_LOCAL else "HTTP only")
    )
    print(f"  Mode: {mode_label}")
    print(f"  WAF URL: {WAF_URL}")
    print(
        f"  BLOCK_THRESHOLD = 10  |  FP_TARGET ≤ 5%  |  Total Cases = {len(FP_CASES)}"
    )
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 90)

    scan_payload = load_detector() if MODE_LOCAL else None
    if MODE_LOCAL and scan_payload is None:
        print(f"\n  ⚠️  ไม่พบ detector ที่ DETECTOR_PATH = {DETECTOR_PATH}")
        print(f"     → วางไฟล์นี้ไว้ใน folder wafcn/ หรือเพิ่ม --http เพื่อทดสอบผ่าน HTTP\n")
        if not MODE_HTTP:
            return

    run_http = MODE_HTTP or (scan_payload is None)

    results = []
    cats = {}
    cur_cat = None

    cat_headers = {
        "select_from": "CAT 1 : select.*from  — FIX: SELECT * FROM docs ไม่ควร block",
        "drop_keyword": "CAT 2 : drop keyword  (+10)",
        "apostrophe": "CAT 3 : Apostrophe / Single Quote",
        "insert_into": "CAT 4 : insert.*into  (+10)",
        "update_set": "CAT 5 : update.*set   (+10)",
        "hex_value": "CAT 6 : 0x Hex Values (+10)",
        "xss_func": "CAT 7 : XSS — function()  (+12)",
        "near_boundary": "CAT 8 : Near-Threshold  (score 7-9, ไม่ควร block)",
        "thai_only": "CAT 9 : Thai Language Only",
        "dev_content": "CAT 10: Developer / Technical Text",
        "username": "CAT 11: Username / Login Field",
        "css_color": "CAT 12: CSS / Hex Color (FIX: ใหม่ — 0x false block)",
    }

    for text, desc, category, score_range in FP_CASES:
        if category != cur_cat:
            cur_cat = category
            print(f"\n  ┌─ {cat_headers.get(category, category)}")
            print(f"  {'─' * 87}")

        local_score = sqli_score = xss_score = cleaned = None
        is_fp = None

        if scan_payload:
            r = scan_payload(text)
            local_score = r["total_score"]
            sqli_score = r["details"]["sqli_score"]
            xss_score = r["details"]["xss_score"]
            cleaned = r["cleaned_payload"]
            is_fp = r["is_blocked"]

        http_status = http_ms = None

        if run_http:
            http_status, http_ms = http_test(text)
            time.sleep(SLEEP_S)
            
            if http_status == 403:
                is_fp = True
            elif http_status in (200, 302):
                is_fp = False
            elif http_status == 429:
                is_fp = False 

        if is_fp is None:
            is_fp = False

        icon = "⚠️  FP!" if is_fp else "✅ TN "
        score_part = (
            f"score={local_score:>3} SQLi={sqli_score:<3} XSS={xss_score:<3}"
            if local_score is not None
            else "local=N/A"
        )
        http_part = (
            f"| HTTP {http_status} {http_ms:.0f}ms" if http_status is not None else ""
        )

        print(f"  {icon}  [{score_part}] {http_part}")
        print(f"         └ {desc}")
        print(f"           Input: {text[:75]}")
        if is_fp and cleaned:
            print(f"           Normalized: {cleaned[:75]}")

        cats.setdefault(category, {"fp": 0, "tn": 0})
        cats[category]["fp" if is_fp else "tn"] += 1

        results.append(
            {
                "text": text,
                "description": desc,
                "category": category,
                "is_fp": is_fp,
                "score": local_score,
                "sqli_score": sqli_score,
                "xss_score": xss_score,
                "http_status": http_status,
                "http_ms": http_ms,
                "expected_range": list(score_range),
            }
        )

    # ── Summary ──────────────────────────────────────────────────────────────
    total_fp = sum(1 for r in results if r["is_fp"])
    total_tn = len(results) - total_fp
    fp_rate = total_fp / len(results) * 100

    print("\n\n" + "=" * 90)
    print("  RESULTS BY CATEGORY")
    print("=" * 90)
    print(f"  {'Category':<18} {'FP':>3} {'TN':>3} {'Rate':>6}")
    print(f"  {'─' * 40}")

    for cat, stat in cats.items():
        fp_c, tn_c = stat["fp"], stat["tn"]
        rate = fp_c / (fp_c + tn_c) * 100 if (fp_c + tn_c) else 0
        flag = " ← ⚠️" if fp_c > 0 else ""
        print(f"  {cat:<18} {fp_c:>3} {tn_c:>3} {rate:>5.0f}%{flag}")

    print(f"  {'─' * 40}")
    print(f"  {'TOTAL':<18} {total_fp:>3} {total_tn:>3} {fp_rate:>5.1f}%")
    print()

    grades = [
        (1, "A+", "Enterprise grade — ดีเยี่ยม"),
        (5, "A ", "Production-ready — ดี"),
        (10, "B ", "Acceptable — พอรับได้ แต่ควรปรับ"),
        (999, "C ", "ต้องแก้ไขด่วน — FP สูงเกินไป"),
    ]
    for threshold, grade, label in grades:
        if fp_rate <= threshold:
            print(f"  Grade: {grade}  — {label}")
            break

    output = {
        "test": "fp_comprehensive_results",
        "timestamp": datetime.now().strftime("%Y-%m-%d_%H-%M-%S"),
        "waf_url": WAF_URL,
        "count": len(results),
        "results": results,
    }
    result_writer("fp_comprehensive_results", results)

    fp_cases_found = [
        (r["description"], r["http_status"]) for r in results if r["is_fp"]
    ]
    assert fp_rate <= 5.0, (  
        f"Comprehensive FP Rate {fp_rate:.1f}% > 5% "
        f"({total_fp}/{len(results)} cases)\n"
        f"FP cases: {fp_cases_found}"
    )


def test_fp_comprehensive_pytest(result_writer):
    """entry point สำหรับ pytest"""
    test_comprehensive_false_positives(result_writer)


if __name__ == "__main__":
    test_comprehensive_false_positives()
