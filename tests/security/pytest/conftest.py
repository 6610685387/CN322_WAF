"""
conftest.py — shared fixtures และ config สำหรับ WAF security tests

FIX v2:
  - รับ WAF_URL ได้ทั้ง WAF_BASE และ WAF_URL (backward compat)
  - เพิ่ม SLEEP_MS default 0.15 เพื่อไม่ให้ rate limit ของ pytest test เอง
"""

import json
import os
import time
from datetime import datetime
from pathlib import Path

import pytest
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Config จาก environment ────────────────────────────────────────────────────
WAF_BASE = os.environ.get("WAF_BASE", os.environ.get("WAF_URL", "https://localhost"))
DIRECT_BASE = os.environ.get("DIRECT_BASE", "http://localhost:5001")
TIMEOUT = int(os.environ.get("TEST_TIMEOUT", "5"))
SLEEP_MS = float(os.environ.get("TEST_SLEEP_MS", "0.15"))  # FIX: 0.1 → 0.15

# ── Results dir ───────────────────────────────────────────────────────────────
RESULTS_DIR = Path(__file__).parent.parent.parent.parent / "tests_result" / "pytest"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

LEGACY_RESULTS_DIR = (
    Path(__file__).parent.parent.parent.parent / "tests_result" / "pytest"
)
LEGACY_RESULTS_DIR.mkdir(parents=True, exist_ok=True)

RUN_TIMESTAMP = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
RUN_DIR = RESULTS_DIR / RUN_TIMESTAMP
RUN_DIR.mkdir(parents=True, exist_ok=True)


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture(scope="session")
def waf_url():
    return WAF_BASE


@pytest.fixture(scope="session")
def direct_url():
    return DIRECT_BASE


@pytest.fixture(scope="session")
def http_timeout():
    return TIMEOUT


@pytest.fixture(autouse=True)
def rate_limit():
    """หน่วงระหว่าง test เพื่อไม่ให้ WAF rate-limit pytest เอง"""
    yield
    time.sleep(SLEEP_MS)


@pytest.fixture
def result_writer(request):
    """
    ส่ง dict ผลลัพธ์ไปบันทึกเป็น JSON หลัง test จบ
    ใช้ใน test: result_writer(results_list)
                หรือ      result_writer(test_name, results_list)  ← backward compat
    ชื่อไฟล์ผลลัพธ์จะตรงกับชื่อ test function โดยอัตโนมัติ
    """
    _store: dict[str, list] = {}
    _test_name: str = request.node.name  # ชื่อ test function จริงๆ

    def write(name_or_results, results: list = None):
        if results is None:
            # เรียกแบบใหม่: result_writer(results_list)
            _store[_test_name] = name_or_results
        else:
            # เรียกแบบเดิม: result_writer("custom_name", results_list)
            # ยังใช้ชื่อ test function เป็นชื่อไฟล์ แต่บันทึก custom_name ใน JSON
            _store[_test_name] = results

    yield write

    # หลัง test: บันทึกผลลัพธ์ลงไฟล์ชื่อเดียวกับ test function
    for name, data in _store.items():
        out_file = RUN_DIR / f"{name}.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "test": name,
                    "timestamp": RUN_TIMESTAMP,
                    "waf_url": WAF_BASE,
                    "count": len(data),
                    "results": data,
                },
                f,
                ensure_ascii=False,
                indent=2,
            )
        print(f"\n📄 Results saved: {out_file}")


def pytest_configure(config):
    config.addinivalue_line("markers", "sqli: SQL Injection test cases")
    config.addinivalue_line("markers", "xss: XSS test cases")
    config.addinivalue_line("markers", "false_positive: False positive test cases")
    config.addinivalue_line("markers", "slow: Tests that take longer than usual")


# ── Terminal Summary Hook ─────────────────────────────────────────────────────


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    """สรุปผลรวมทั้งหมดแบบ custom ที่ terminal หลัง session จบ"""
    passed = len(terminalreporter.stats.get("passed", []))
    failed = len(terminalreporter.stats.get("failed", []))
    error = len(terminalreporter.stats.get("error", []))
    skipped = len(terminalreporter.stats.get("skipped", []))
    total = passed + failed + error + skipped

    pct_pass = (passed / total * 100) if total > 0 else 0.0
    pct_fail = ((failed + error) / total * 100) if total > 0 else 0.0

    # สี ANSI
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    bar_width = 40
    fill = int(bar_width * pct_pass / 100) if total > 0 else 0
    bar = f"{GREEN}{'█' * fill}{RED}{'░' * (bar_width - fill)}{RESET}"

    STATUS_ICON = (
        f"{GREEN}✅ ALL PASSED{RESET}"
        if failed == 0 and error == 0
        else f"{RED}❌ SOME FAILED{RESET}"
    )

    terminalreporter.write_sep("=", "WAF TEST SUITE — FINAL SUMMARY", bold=True)
    terminalreporter.write_line("")
    terminalreporter.write_line(f"  {BOLD}Target WAF :{RESET}  {WAF_BASE}")
    terminalreporter.write_line(f"  {BOLD}Timestamp  :{RESET}  {RUN_TIMESTAMP}")
    terminalreporter.write_line("")
    terminalreporter.write_line(f"  {BOLD}Total Tests:{RESET}  {total}")
    terminalreporter.write_line(
        f"  {GREEN}{BOLD}  ✔ Passed  :{RESET}  {passed}  ({pct_pass:.1f}%)"
    )
    if failed:
        terminalreporter.write_line(
            f"  {RED}{BOLD}  ✖ Failed  :{RESET}  {failed}  ({pct_fail:.1f}%)"
        )
    if error:
        terminalreporter.write_line(f"  {RED}{BOLD}  ✖ Errors  :{RESET}  {error}")
    if skipped:
        terminalreporter.write_line(f"  {YELLOW}{BOLD}  ⏭ Skipped :{RESET}  {skipped}")
    terminalreporter.write_line("")
    terminalreporter.write_line(f"  Progress:  [{bar}]  {pct_pass:.1f}%")
    terminalreporter.write_line("")
    terminalreporter.write_line(f"  Status:    {STATUS_ICON}")
    terminalreporter.write_line("")

    # แสดงรายชื่อ tests ที่ fail (ถ้ามี)
    failed_items = terminalreporter.stats.get("failed", [])
    error_items = terminalreporter.stats.get("error", [])
    if failed_items or error_items:
        terminalreporter.write_line(f"  {RED}{BOLD}Failed / Error Tests:{RESET}")
        for item in failed_items + error_items:
            node = getattr(item, "nodeid", str(item))
            terminalreporter.write_line(f"    {RED}✖{RESET} {node}")
        terminalreporter.write_line("")

    terminalreporter.write_sep("=", "", bold=True)
