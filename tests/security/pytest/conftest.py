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


@pytest.fixture(scope="session")
def result_writer():
    """
    ส่ง dict ผลลัพธ์ไปบันทึกเป็น JSON หลัง session จบ
    ใช้ใน test: result_writer(test_name, results_list)
    """
    _store: dict[str, list] = {}

    def write(test_name: str, results: list):
        _store[test_name] = results

    yield write

    # หลัง session: บันทึกทุก test ลงไฟล์
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
