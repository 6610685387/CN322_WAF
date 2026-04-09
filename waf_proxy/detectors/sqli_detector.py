import re

class SQLDetector:
    def __init__(self):      
        # รายการกฎ (Regex, Base Score)
        self.rules = [
            # 1. Critical Exfiltration & Execution
            # ใช้ re.DOTALL ในการรันเพื่อให้ . match newline (จัดการข้อ 1)
            (r"\bunion\b.*\bselect\b", 15),
            (r"\binformation_schema\b", 12),
            (r"\binto\s+(outfile|dumpfile)\b", 12),
            (r"\bload_file\b", 12),
            
            # 2. Blind & Time-based Functions (จัดการข้อ 5)
            (r"\bsleep\s*\(", 10),
            (r"\bbenchmark\s*\(", 10),
            (r"\bpg_sleep\s*\(", 10),
            (r"\bwaitfor\s+delay\b", 10),
            (r"\b(ascii|bin|char|hex|unhex|base64|ord|mid|substr|substring|concat|group_concat)\s*\(", 7),
            
            # 3. Logic, Tautology & Hex (จัดการข้อ 4)
            (r"\b(or|and)\b\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?", 10),
            (r"\b(or|and)\b\s+(\d+=\d+|true\b)", 8),
            (r"0x[0-9a-f]{2,}", 10), # Hex detection (เช่น 0x5345...)
            
            # 4. Advanced Structure Abuse (จัดการข้อ 6)
            (r"\border\s+by\s+\d+", 8),
            (r"\bgroup\s+by\s+\d+", 8),
            (r"\bhaving\b\s+\d+=\d+", 10),
            (r"\bprocedure\s+analyse\s*\(", 10), # ท่าแฮก MySQL เก่า
            
            # 5. Combined Keywords (ลด False Positive - จัดการข้อ 3 & 7)
            # แทนที่จะดัก select เดี่ยวๆ เราดักโครงสร้างที่ดูเป็น query จริงๆ
            (r"\bselect\b.*\bfrom\b", 10),
            (r"\binsert\b.*\binto\b", 10),
            (r"\bupdate\b.*\bset\b", 10),
            (r"\bdelete\b.*\bfrom\b", 10),
            
            # 6. Basic Keywords (ให้คะแนนน้อยลงเพื่อกัน Noise)
            (r"\bselect\b", 3),
            (r"\bfrom\b", 2),
            (r"\bwhere\b", 2),
            (r"\bdrop\b", 10),
            
            # 7. Stacked Queries & Comments
            (r"['\";|]", 2),
            (r"--", 4),
            (r"/\*!", 8), # ตรวจเจอ MySQL Wrapper แม้จะถูก normalize ไปแล้ว (จัดการข้อ 2)
            (r"\(\s*select\b", 10)
        ]
        
    def get_score(self, input_string):
        if not input_string:
            return 0
            
        total_score = 0
        
        # วนลูปเช็คตามกฎ
        for pattern, score in self.rules:
            # ใช้ flags=re.DOTALL เพื่อให้ . match ขึ้นบรรทัดใหม่ (แก้ข้อ 1)
            # ใช้ flags=re.IGNORECASE เพราะแฮกเกอร์ใช้ SeLeCt
            matches = re.findall(pattern, input_string, re.IGNORECASE | re.DOTALL)
            
            if matches:
                # ครั้งแรกได้คะแนนเต็ม ครั้งต่อไปบวกเพิ่มทีละนิด
                occurrence_bonus = (len(matches) - 1) * 2
                total_score += score + max(0, occurrence_bonus)

        # --- การตรวจสอบเชิงบริบทขั้นสูง (Contextual) ---
        
        # 1. การเช็คเครื่องหมายคำพูด (Quote Imbalance)
        # แฮกเกอร์มักใช้ ' เพื่อเบรกสตริง ถ้าเจอจำนวนคี่ (Odd) มักจะเป็นการฉีดคำสั่ง
        if (input_string.count("'") % 2 != 0) or (input_string.count('"') % 2 != 0):
            total_score += 5

        # 2. การเช็ค Stacked Query (จบคำสั่งแล้วเริ่มใหม่)
        if re.search(r";\s*\b(select|insert|update|drop|delete|set)\b", input_string, re.IGNORECASE | re.DOTALL):
            total_score += 12

        return total_score

'''        
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
            return True
            
        return False
'''