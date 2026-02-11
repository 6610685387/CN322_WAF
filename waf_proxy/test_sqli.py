# เปลี่ยนการ import เป็นไฟล์ใหม่
from sqli_detector import SQLDetector

# สร้าง Instance ของคลาสใหม่
waf = SQLDetector()

print("--- 🕵️‍♀️ เริ่มทดสอบ SQL Injection Hunter Rules ---")

sql_tests = [
    # เคสปกติ (ต้องผ่าน)
    ("admin", False),
    ("hello world", False),
    # เคสโจมตี (ต้องบล็อก)
    ("admin' OR 1=1 --", True),  # Basic Bypass
    ("UNION SELECT user, pass", True),  # Union Based
    ("SELECT * FROM users", True),  # Direct Select
    ("DELETE FROM users", True),  # 🆕 Destructive (ของใหม่)
    ("INSERT INTO users VALUES", True),  # 🆕 Injection (ของใหม่)
    ("admin'; EXEC xp_cmdshell", True),  # 🆕 Command Exec (ของใหม่)
]

print(f"{'INPUT':<30} | {'STATUS':<10} | {'RESULT'}")
print("-" * 55)

for text, expected in sql_tests:
    is_blocked = waf.check_sqli(text)

    status_text = "🚫 BLOCKED" if is_blocked else "✅ PASS"
    is_correct = "ถูกต้อง" if is_blocked == expected else "❌ ผิดพลาด"

    print(f"{text:<30} | {status_text:<10} | {is_correct}")
