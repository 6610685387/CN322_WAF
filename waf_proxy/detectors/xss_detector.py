import re

class XSSDetector:
    def __init__(self):
        # รายการกฎ (Regex, Base Score)
        self.rules = [
            # 1. Critical Tags & DOM Assignments (จัดการข้อ 1 & 2)
            (r"<\s*script\b", 15),
            (r"\b(innerhtml|outerhtml|document\.write)\s*=", 12),
            (r"\blocation\s*=\s*['\"]?\s*javascript:", 15),
            (r"<\s*iframe[^>]+srcdoc\s*=", 12), # จัดการ iframe srcdoc
            
            # 2. Event Handlers (on* family)
            (r"\bon[a-z]+\s*=", 10), 
            
            # 3. Pseudo-protocols & URI XSS
            (r"javascript\s*:", 15),
            (r"data\s*:\s*text/html", 15),
            
            # 4. JavaScript Functions (Sinks)
            (r"\b(alert|prompt|confirm|eval|setTimeout|setInterval)\s*\(", 10),
            (r"\bString\.fromCharCode\s*\(", 12),
            (r"\bdocument\.(cookie|location|domain)\b", 10),
            
            # 5. Dangerous HTML Tags
            (r"<\s*(iframe|object|embed|applet|meta|link|base|form|style)\b", 10),
            (r"<\s*(svg|math|canvas|details|video|audio)\b", 8),
            
            # 6. Context Breaking & Polyglots (จัดการข้อ 4)
            # ดักจับพวก "><script หรือ '><img
            (r"['\"]?\s*>\s*<\s*\w+\b", 12),
            (r"javascript\s*:\s*/*\s*`\s*/*\s*'\s*/*\s*\"\s*/*\s*\(", 15), # Polyglot pattern
            
            # 7. Obfuscation Patterns
            (r"`\s*\${", 8),
            (r"atob\s*\(", 8),
            (r"\\\s*x[0-9a-f]{2}", 5)
        ]

    def get_score(self, input_string):
        if not input_string:
            return 0
            
        total_score = 0
        
        # วนลูปเช็คตามกฎ Regex ปกติ
        for pattern, score in self.rules:
            matches = re.findall(pattern, input_string, re.IGNORECASE | re.DOTALL)
            if matches:
                # Dynamic Scoring: เจอซ้ำได้โบนัส
                occurrence_bonus = (len(matches) - 1) * 2
                total_score += score + max(0, occurrence_bonus)

        # --- 🛡️ การตรวจสอบเชิงบริบทขั้นสูง (Heuristic & Correlation) ---

        # 1. Keyword Correlation (จัดการข้อ 6)
        # ถ้าเจอทั้ง Tag และ Function อันตรายพร้อมกัน คะแนนต้องพุ่ง
        if "<script" in input_string.lower():
            if any(func in input_string.lower() for func in ["alert(", "eval(", "prompt(", "confirm("]):
                total_score += 15 # สูงมาก เพราะชัดเจนว่าเป็นการรันสคริปต์

        # 2. Improved Tag Balance (จัดการข้อ 5)
        # ตรวจสอบการพยายามทำ Tag Break (มี < แต่จงใจไม่ปิด >)
        if "<" in input_string and ">" not in input_string:
            total_score += 10 # เสี่ยงมาก มักเป็นการฉีดเพื่อพัง Context เดิม
        
        # 3. DOM-based Assignment Correlation (จัดการข้อ 1 เพิ่มเติม)
        # ถ้ามีการใช้ innerHTML หรือ location= ร่วมกับการพยายามฉีดสคริปต์
        if re.search(r"\b(innerhtml|location)\b", input_string, re.IGNORECASE):
            if any(char in input_string for char in ["<", ">", "javascript:"]):
                total_score += 10

        # 4. Bracket & Quote Imbalance
        if input_string.count("(") != input_string.count(")"):
            total_score += 5
        if (input_string.count("'") % 2 != 0) or (input_string.count('"') % 2 != 0):
            total_score += 5

        return total_score


''' def check_xss(self, input_string):
        """
        ตรวจสอบว่า Input มี XSS Payload หรือไม่
        """
        if not input_string:
            return False

        # 1. Decode ข้อมูลก่อน (เช่นแปลง %3Cscript%3E เป็น <script>)
        
        decoded_string = unquote(input_string)

        # 2. ตรวจสอบด้วย Regex
        if self.xss_pattern.search(decoded_string):
            return True  

        return False 
'''