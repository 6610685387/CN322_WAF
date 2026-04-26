"""
WAF Security Evaluation - XSS Detection Test
=============================================
FIX v2:
  - เพิ่ม HTML entity encoded XSS (&#60;script&#62;) — เดิมเป็น TN ไม่ควรผ่าน!
  - เพิ่ม CSS expression, meta refresh, template literal
  - เพิ่ม POST body XSS test
  - ปรับ assertion threshold → 85%
  - แยก benign HTML (<b>, <3) ออกเป็น expected TN ชัดเจน
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
SLEEP_MS = 0.1

XSS_PAYLOADS = [
    # ── Classic Script Tags ──────────────────────────────────────────────────
    ("<script>alert(1)</script>", True, "Classic Script Alert"),
    ("<script>alert('XSS')</script>", True, "Script Alert String"),
    ("<SCRIPT>alert(1)</SCRIPT>", True, "Script Uppercase"),
    ("<scr<script>ipt>alert(1)</scr</script>ipt>", True, "Nested Script Tag"),
    # ── Event Handlers ───────────────────────────────────────────────────────
    ("<img src=x onerror=alert(1)>", True, "onerror Event"),
    ("<body onload=alert(1)>", True, "onload Body"),
    ("<svg onload=alert(1)>", True, "SVG onload"),
    ("<input onfocus=alert(1) autofocus>", True, "onfocus autofocus"),
    ("<a onclick=alert(1)>click</a>", True, "onclick Anchor"),
    ("<details open ontoggle=alert(1)>", True, "ontoggle details"),  # FIX: ใหม่
    ("<marquee onstart=alert(1)>", True, "onstart marquee"),  # FIX: ใหม่
    ("<video autoplay onplay=alert(1)>", True, "onplay video"),  # FIX: ใหม่
    # ── JavaScript URI ───────────────────────────────────────────────────────
    ("<a href='javascript:alert(1)'>XSS</a>", True, "JS URI href"),
    ("<iframe src='javascript:alert(1)'></iframe>", True, "JS URI iframe"),
    # ── DOM Based ────────────────────────────────────────────────────────────
    (
        "<div id='x'></div><script>document.write('XSS')</script>",
        True,
        "document.write",
    ),
    ("'><script>eval(atob('YWxlcnQoMSk='))</script>", True, "eval + atob"),
    # ── Encoding Bypass ──────────────────────────────────────────────────────
    ("%3Cscript%3Ealert(1)%3C/script%3E", True, "URL Encoded Script"),
    # FIX: HTML entity encoding — เดิมเป็น expected=True แต่ยังหลุด!
    # nginx pre-screen เดิมไม่มี &#60; pattern → ต้องเพิ่มแล้ว retest
    ("&#60;script&#62;alert(1)&#60;/script&#62;", True, "HTML Entity Script"),  # FIX
    ("<scr\x00ipt>alert(1)</scr\x00ipt>", True, "Null Byte Bypass"),
    (
        "&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;",
        True,
        "Hex HTML Entity Script",
    ),  # FIX: ใหม่
    # ── Data URI ─────────────────────────────────────────────────────────────
    ("<iframe src='data:text/html,<script>alert(1)</script>'>", True, "Data URI HTML"),
    # ── Template Literal / Modern JS ────────────────────────────────────────
    ("`<img src=x onerror=alert\`1\`>`", True, "Template Literal XSS"),  # FIX: ใหม่
    # ── ควรผ่าน (Benign) — TN ────────────────────────────────────────────────
    ("hello world", False, "Normal Text"),
    ("search query with <b>bold</b>", False, "Simple HTML Bold"),
    ("click here for more", False, "Normal CTA"),
    ("My name is <n> and I am a user", False, "Angle Brackets Name"),
    ("score > 90 and rank < 10", False, "Math Comparison"),
    ("<3 I love you", False, "Heart Symbol"),
]

ENDPOINT = f"{WAF_BASE}/search?q={{payload}}"

# POST XSS cases
POST_XSS_CASES = [
    (
        f"{WAF_BASE}/login",
        {"username": "<script>alert(1)</script>", "password": "x"},
        True,
        "POST Login XSS Script",
    ),
    (
        f"{WAF_BASE}/login",
        {"username": "<img src=x onerror=alert(1)>", "password": "x"},
        True,
        "POST Login XSS onerror",
    ),
    (f"{WAF_BASE}/search", {"q": "<svg onload=alert(1)>"}, True, "POST Search XSS SVG"),
    (
        f"{WAF_BASE}/login",
        {"username": "alice", "password": "x"},
        False,
        "POST Login Normal",
    ),
]


def run_get(url, expected_blocked):
    try:
        start = time.time()
        r = requests.get(url, verify=False, timeout=TIMEOUT, allow_redirects=False)
        latency_ms = (time.time() - start) * 1000
        ab = r.status_code == 403
        return {
            "status_code": r.status_code,
            "blocked": ab,
            "outcome": _outcome(expected_blocked, ab),
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
        ab = r.status_code == 403
        return {
            "status_code": r.status_code,
            "blocked": ab,
            "outcome": _outcome(expected_blocked, ab),
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


def test_xss_detection(result_writer):
    print("=" * 70)
    print("  WAF Security Evaluation - XSS Detection Test (GET)")
    print(f"  Target: {WAF_BASE}")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    results = []
    tp = fn = tn = fp = err = 0

    for payload, expected_blocked, desc in XSS_PAYLOADS:
        url = ENDPOINT.format(payload=requests.utils.quote(payload))
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
                "payload": payload[:80],
                "expected_blocked": expected_blocked,
                "actually_blocked": result["blocked"],
                "outcome": outcome,
                "http_status": result["status_code"],
                "latency_ms": result["latency_ms"],
            }
        )

    _print_summary("XSS GET", tp, fn, tn, fp, err)
    result_writer("xss_results", results)
    _assert(tp, fn, tn, fp, err, "XSS GET")


def test_xss_post(result_writer):
    """FIX: ทดสอบ POST body XSS"""
    print("\n" + "=" * 70)
    print("  WAF Security Evaluation - XSS Detection Test (POST)")
    print(f"  Target: {WAF_BASE}")
    print("=" * 70)

    results = []
    tp = fn = tn = fp = err = 0

    for url, data, expected_blocked, desc in POST_XSS_CASES:
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

    _print_summary("XSS POST", tp, fn, tn, fp, err)
    result_writer("xss_post_results", results)
    _assert(tp, fn, tn, fp, err, "XSS POST")


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
        f"[{label}] XSS Detection Rate {det_rate:.1f}% < 85% "
        f"(TP={tp}, FN={fn}) — WAF พลาด XSS attack เยอะเกินไป"
    )
    assert fp_rate <= 10.0, (
        f"[{label}] False Positive Rate {fp_rate:.1f}% > 10% "
        f"(FP={fp}, TN={tn}) — WAF บล็อก benign traffic มากเกินไป"
    )


if __name__ == "__main__":
    test_xss_detection(lambda name, data: None)
    test_xss_post(lambda name, data: None)
