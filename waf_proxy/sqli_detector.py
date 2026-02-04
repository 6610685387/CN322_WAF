import re

class SQLDetector:
    def __init__(self):
        # 🛡️ Role 2: SQL Injection Patterns
        # รวม Pattern ยอดฮิตที่ Hacker ใช้โจมตี Database
        self.sql_patterns = [
            # 1. Basic Injection
            r"'",                # Single Quote (จุดเริ่มของหายนะ)
            r"--",               # Comment SQL
            r"#",                # Comment แบบ MySQL
            
            # 2. Authentication Bypass
            r"or\s+1=1",         # เงื่อนไขเป็นจริงเสมอ
            
            # 3. Data Extraction (ดูดข้อมูล)
            r"union\s+select",   # รวมตาราง
            r"select\s+.*\s+from", # ดึงข้อมูลตรงๆ
            
            # 4. Data Modification (ทำลายข้อมูล) - เพิ่มส่วนนี้เข้ามา
            r"insert\s+into",    # เพิ่มข้อมูลปลอม
            r"update\s+.*set",   # แอบเปลี่ยนค่า
            r"delete\s+from",    # ลบข้อมูลทิ้ง
            r"drop\s+table",     # ลบตารางทิ้ง (หายนะสูงสุด)
            
            # 5. Advanced Techniques
            r"exec(\s|\()",      # สั่งรันคำสั่ง System
            r"sleep\(",          # ทำให้ Server หน่วง (Time-based SQLi)
            r"benchmark\("       # ทำให้ Server ค้าง
        ]
        
    def check_sqli(self, input_string):
        """
        ตรวจสอบว่า Input มีความพยายามโจมตี SQL Injection หรือไม่
        """
        if not input_string:
            return False
            
        # รวมกฎทั้งหมด
        combined_pattern = "|".join(self.sql_patterns)
        
        # ตรวจสอบ (Ignore Case: เล็กใหญ่มีค่าเท่ากัน)
        if re.search(combined_pattern, input_string, re.IGNORECASE):
            return True # 🚨 เจอโจร!
            
        return False # ✅ ปลอดภัย