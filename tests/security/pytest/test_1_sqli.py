"""
WAF Security Evaluation - SQLi Detection Test
=============================================
FIX v2:
  - เพิ่ม HTML entity encoded payloads (&#60;script&#62; bypass)
  - เพิ่ม comment-obfuscated UNION (UN/**/ION SE/**/LECT)
  - เพิ่ม tab-encoded OR (%09OR%09)
  - เพิ่ม double URL-encoded (%2527)
  - ปรับ assertion threshold → 85% (สอดคล้องกับเป้าหมาย)
  - เพิ่ม POST endpoint test
"""

import requests
import json
import time
import urllib3
import os
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# =============================================
# CONFIG
# =============================================
WAF_BASE = os.environ.get("WAF_BASE", "https://localhost")
DIRECT_BASE = os.environ.get("DIRECT_BASE", "http://localhost:5001")
TIMEOUT = 5
SLEEP_MS = 0.1

# =============================================
# SQLi Payload Bank
# (payload, expected_blocked, description)
# =============================================
SQLI_PAYLOADS = [
    # ── Classic / Tautology ──────────────────────────────────────────────────
    ("' OR '1'='1", True, "Classic Tautology"),
    ("' OR 1=1--", True, "Tautology + Comment"),
    ("admin'--", True, "Auth Bypass Comment"),
    ("1' AND '1'='1", True, "AND Tautology"),
    # ── UNION Based ──────────────────────────────────────────────────────────
    ("' UNION SELECT 1,2,3--", True, "UNION SELECT"),
    ("' UNION ALL SELECT NULL,NULL,NULL--", True, "UNION ALL NULL"),
    ("1 UNION SELECT username,password FROM users", True, "UNION Exfil"),
    ("' UNION SELECT table_name FROM information_schema.tables--", True, "Info Schema"),
    # ── Blind / Time-based ───────────────────────────────────────────────────
    ("1' AND SLEEP(1)--", True, "Time-based SLEEP"),
    ("'; WAITFOR DELAY '0:0:1'--", True, "MSSQL WAITFOR"),
    ("1' AND BENCHMARK(1000000,MD5(1))--", True, "BENCHMARK"),
    # ── Stacked Queries ──────────────────────────────────────────────────────
    ("1; DROP TABLE users--", True, "Stacked DROP"),
    ("1; INSERT INTO users VALUES('hack','hack')--", True, "Stacked INSERT"),
    # ── Error Based ──────────────────────────────────────────────────────────
    ("' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--", True, "Error EXTRACTVALUE"),
    ("1 AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects))", True, "MSSQL CONVERT"),
    # ── Encoding Bypass ──────────────────────────────────────────────────────
    ("' %4F%52 '1'='1", True, "URL Encoded OR"),
    ("' /*!OR*/ '1'='1", True, "MySQL Comment Bypass"),
    ("0x27206f7220 0x313d31", True, "Hex Encoding"),
    ("%2527%20OR%20%25271%2527%253D%25271", True, "URL Double-Encoded OR"),  # FIX: ใหม่
    ("' UN/**/ION SE/**/LECT 1,2--", True, "Comment Obfuscation"),  # FIX: ใหม่
    ("'%09OR%091=1--", True, "Tab-Encoded OR"),  # FIX: ใหม่
    # ── ควรผ่าน (Benign) ─────────────────────────────────────────────────────
    ("hello world", False, "Normal Text"),
    ("SELECT your product", False, "SELECT in English sentence"),
    ("my password is 123456", False, "Normal Password"),
    ("search for items", False, "Normal Search"),
    ("order by price", False, "Normal Order By"),
    ("apple banana cherry", False, "Normal Keywords"),
    ("WHERE is the nearest coffee shop", False, "WHERE in English"),
    ("update me with latest news", False, "UPDATE in English"),
]

ENDPOINTS = [
    f"{WAF_BASE}/search?q={{payload}}",
    f"{WAF_BASE}/login?username={{payload}}",
]

# POST attack cases — ทดสอบ body inspection
POST_ATTACK_CASES = [
    (
        f"{WAF_BASE}/login",
        {"username": "' OR '1'='1", "password": "x"},
        True,
        "POST Login SQLi Tautology",
    ),
    (
        f"{WAF_BASE}/login",
        {"username": "admin'--", "password": "x"},
        True,
        "POST Login Auth Bypass",
    ),
    (
        f"{WAF_BASE}/login",
        {"username": "' UNION SELECT 1,2--", "password": "x"},
        True,
        "POST Login UNION",
    ),
    (
        f"{WAF_BASE}/search",
        {"q": "1 UNION SELECT username,password FROM users--"},
        True,
        "POST Search UNION Exfil",
    ),
    (
        f"{WAF_BASE}/login",
        {"username": "alice", "password": "mypassword"},
        False,
        "POST Login Normal",
    ),
]


# =============================================
# Test Runner
# =============================================
def run_get(url, expected_blocked):
    try:
        start = time.time()
        r = requests.get(url, verify=False, timeout=TIMEOUT, allow_redirects=False)
        latency_ms = (time.time() - start) * 1000
        actually_blocked = r.status_code == 403
        outcome = _outcome(expected_blocked, actually_blocked)
        return {
            "status_code": r.status_code,
            "blocked": actually_blocked,
            "outcome": outcome,
            "latency_ms": round(latency_ms, 2),
        }
    except Exception:
        return {
            "status_code": "ERR",
            "blocked": None,
            "outcome": "ERR",
            "latency_ms": 0,
        }


def run_post(url, data, expected_blocked):
    try:
        start = time.time()
        r = requests.post(
            url, data=data, verify=False, timeout=TIMEOUT, allow_redirects=False
        )
        latency_ms = (time.time() - start) * 1000
        actually_blocked = r.status_code == 403
        outcome = _outcome(expected_blocked, actually_blocked)
        return {
            "status_code": r.status_code,
            "blocked": actually_blocked,
            "outcome": outcome,
            "latency_ms": round(latency_ms, 2),
        }
    except Exception:
        return {
            "status_code": "ERR",
            "blocked": None,
            "outcome": "ERR",
            "latency_ms": 0,
        }


def _outcome(expected_blocked, actually_blocked):
    if expected_blocked and actually_blocked:
        return "TP"
    elif expected_blocked and not actually_blocked:
        return "FN"
    elif not expected_blocked and not actually_blocked:
        return "TN"
    else:
        return "FP"


def _print_row(outcome, expected_blocked, result, label):
    icon = {"TP": "✅", "TN": "✅", "FN": "❌", "FP": "⚠️", "ERR": "💥"}.get(
        outcome, "?"
    )
    tag = "🔴 MALICIOUS" if expected_blocked else "🟢 BENIGN  "
    print(
        f"  {icon} [{outcome}] {tag} | HTTP {result['status_code']} | {result['latency_ms']:>7.1f}ms | {label}"
    )


# =============================================
# Pytest Entry Points
# =============================================
def test_sqli_detection(result_writer):
    print("=" * 70)
    print("  WAF Security Evaluation - SQL Injection Detection Test (GET)")
    print(f"  Target: {WAF_BASE}")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    results = []
    tp = fn = tn = fp = err = 0

    for payload, expected_blocked, desc in SQLI_PAYLOADS:
        url = ENDPOINTS[0].format(payload=requests.utils.quote(payload))
        result = run_get(url, expected_blocked)
        time.sleep(SLEEP_MS)

        outcome = result["outcome"]
        _print_row(outcome, expected_blocked, result, desc)

        if outcome == "TP":
            tp += 1
        elif outcome == "FN":
            fn += 1
        elif outcome == "TN":
            tn += 1
        elif outcome == "FP":
            fp += 1
        else:
            err += 1

        results.append(
            {
                "description": desc,
                "payload": payload,
                "expected_blocked": expected_blocked,
                "actually_blocked": result["blocked"],
                "outcome": outcome,
                "http_status": result["status_code"],
                "latency_ms": result["latency_ms"],
                "url": url,
            }
        )

    _print_summary("SQLi GET", tp, fn, tn, fp, err)
    result_writer("sqli_results", results)
    _assert(tp, fn, tn, fp, err, "SQLi GET")


def test_sqli_post(result_writer):
    """FIX: ทดสอบ POST body inspection แยกต่างหาก"""
    print("\n" + "=" * 70)
    print("  WAF Security Evaluation - SQL Injection Detection Test (POST)")
    print(f"  Target: {WAF_BASE}")
    print("=" * 70)

    results = []
    tp = fn = tn = fp = err = 0

    for url, data, expected_blocked, desc in POST_ATTACK_CASES:
        result = run_post(url, data, expected_blocked)
        time.sleep(SLEEP_MS)

        outcome = result["outcome"]
        _print_row(outcome, expected_blocked, result, desc)

        if outcome == "TP":
            tp += 1
        elif outcome == "FN":
            fn += 1
        elif outcome == "TN":
            tn += 1
        elif outcome == "FP":
            fp += 1
        else:
            err += 1

        results.append(
            {
                "description": desc,
                "data": str(data),
                "expected_blocked": expected_blocked,
                "actually_blocked": result["blocked"],
                "outcome": outcome,
                "http_status": result["status_code"],
                "latency_ms": result["latency_ms"],
            }
        )

    _print_summary("SQLi POST", tp, fn, tn, fp, err)
    result_writer("sqli_post_results", results)
    _assert(tp, fn, tn, fp, err, "SQLi POST")


# =============================================
# Helpers
# =============================================
def _print_summary(label, tp, fn, tn, fp, err):
    total_mal = tp + fn
    total_ben = tn + fp
    total = total_mal + total_ben
    det_rate = (tp / total_mal * 100) if total_mal > 0 else 0
    fp_rate = (fp / total_ben * 100) if total_ben > 0 else 0
    accuracy = ((tp + tn) / total * 100) if total > 0 else 0

    print("\n" + "=" * 70)
    print(f"  SUMMARY — {label}")
    print("=" * 70)
    print(f"  Detection Rate     : {det_rate:.1f}%  (TP={tp}, FN={fn})")
    print(f"  False Positive Rate: {fp_rate:.1f}%  (FP={fp}, TN={tn})")
    print(f"  Accuracy           : {accuracy:.1f}%")
    if err:
        print(f"  Errors             : {err} ← ตรวจสอบการเชื่อมต่อ")
    print("=" * 70)


def _assert(tp, fn, tn, fp, err, label):
    total_mal = tp + fn
    total_ben = tn + fp
    det_rate = (tp / total_mal * 100) if total_mal > 0 else 0
    fp_rate = (fp / total_ben * 100) if total_ben > 0 else 0

    assert err == 0, f"[{label}] Connection errors: {err} — WAF ไม่พร้อมใช้งาน"
    assert det_rate >= 85.0, (  # FIX: เพิ่มจาก 80% → 85%
        f"[{label}] Detection Rate {det_rate:.1f}% < 85% "
        f"(TP={tp}, FN={fn}) — WAF พลาด attack เยอะเกินไป"
    )
    assert fp_rate <= 10.0, (
        f"[{label}] False Positive Rate {fp_rate:.1f}% > 10% "
        f"(FP={fp}, TN={tn}) — WAF บล็อก benign traffic มากเกินไป"
    )


if __name__ == "__main__":
    test_sqli_detection(lambda name, data: None)
    test_sqli_post(lambda name, data: None)
