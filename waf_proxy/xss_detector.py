import re
from urllib.parse import unquote


class XSSDetector:
    def __init__(self):
        # รวม Pattern การโจมตี XSS จาก payloads.txt
        # เราใช้ re.VERBOSE เพื่อให้เขียน Regex แยกบรรทัดได้ อ่านง่ายขึ้น
        self.xss_pattern = re.compile(
            r"""
            (
                <\s*script              # <script tag
                |javascript\s*:         # javascript: protocol
                |on\w+\s*=              # Event handlers (onload=, onerror=, onclick=)
                |alert\s*\(             # alert(...)
                |prompt\s*\(            # prompt(...)
                |confirm\s*\(           # confirm(...)
                |document\.cookie       # ขโมย Cookie
                |<\s*(iframe|object|embed|svg|img|body) # Tag อันตรายอื่นๆ
            )
        """,
            re.IGNORECASE | re.VERBOSE,
        )

    def check_xss(self, input_string):
        """
        ตรวจสอบว่า Input มี XSS Payload หรือไม่
        """
        if not input_string:
            return False

        # 1. Decode ข้อมูลก่อน (เช่นแปลง %3Cscript%3E เป็น <script>)
        # เพื่อกัน Hacker แอบส่งโค้ดแบบ Encoded มา
        decoded_string = unquote(input_string)

        # 2. ตรวจสอบด้วย Regex
        if self.xss_pattern.search(decoded_string):
            return True  # 🚨 เจอโจร XSS!

        return False  # ✅ ปลอดภัย
