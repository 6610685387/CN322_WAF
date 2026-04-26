import re
from .normalizer import recursive_normalize


class SQLDetector:
    def __init__(self, threshold: int = 12):
        self.threshold = threshold
        # รายการกฎ (Regex, Base Score)
        self.rules = [
            # 1. Critical Exfiltration & Execution
            (r"\bunion\b.*\bselect\b", 18),
            (r"\bselect\b.*\bunion\b", 18),
            (r"\binformation_schema\b", 14),
            (r"\binto\s+(outfile|dumpfile)\b", 14),
            (r"\bload_file\b", 14),
            (r"\bsys\.objects\b|sysobjects\b", 14),
            (r"\bmysql\.user\b|mysql\.password\b", 14),
            
            # 2. Blind & Time-based Functions
            (r"\bsleep\s*\(\s*\d+", 12),
            (r"\bbenchmark\s*\(\s*\d+", 12),
            (r"\bpg_sleep\s*\(", 12),
            (r"\bwaitfor\s+delay\b", 12),
            (r"\bdbms_lock\.sleep\b", 12),
            (r"\bpause\s*\(", 10),
            (r"\bdelay\s*\(", 10),
            
            # 3. String & Obfuscation Functions (Higher weights for common SQLi)
            (r"\b(char|chr|chr|ascii|bin|hex|unhex|base64|ord|mid|substr|substring|concat|concat_ws|group_concat)\s*\(", 9),
            (r"\b(instr|locate|position|lower|upper|trim|ltrim|rtrim|length|len)\s*\(", 6),
            
            # 4. Boolean-based SQLi (Critical)
            (r"\b(and|or)\b\s+\d+\s*=\s*\d+", 11),
            (r"\b(and|or)\b\s+(?:true|false)\b", 11),
            (r"\b(and|or)\b\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?", 10),
            (r"\s*(?:and|or)\s+(?:1|true)\s*(?:--|;|$)", 12),
            (r"\s*(?:and|or)\s+\d+\s*(?:--|;|$)", 11),
            # Tautology with + as space separator (URL-decoded: '+or+'1'='1)
            (r"['\"][\+\s]*(?:or|and)[\+\s]*['\"]", 12),
            # Quote-flanked tautology: ' or '1'='1 or similar
            (r"(?:or|and)[\+\s]*['\"]?\w+['\"]?\s*=\s*['\"]?\w", 11),
            
            # 5. Hex & Encoding
            (r"0x[0-9a-fA-F]{4,}", 11),
            (r"0x[0-9a-fA-F]{2,}\s*(?:and|or|,|;)", 13),
            (r"0x\d+", 8),
            
            # 6. Advanced Structure Abuse
            (r"\border\s+by\s+\d+", 10),
            (r"\bgroup\s+by\s+.*\bhaving\b", 11),
            (r"\bhaving\b\s+\d+=\d+", 12),
            (r"\bprocedure\s+analyse\s*\(", 12),
            (r"\bcase\s+when\b.*\bthen\b", 10),
            (r"\bif\s*\([^)]+\)\s*(?:select|union)", 12),
            
            # 7. Data Manipulation & Combined Keywords
            (r"\bselect\b.*\bfrom\b.*\bwhere\b", 12),
            (r"\binsert\b.*\binto\b.*\bvalues\b", 12),
            (r"\bupdate\b.*\bset\b.*\bwhere\b", 12),
            (r"\bdelete\b.*\bfrom\b.*\bwhere\b", 12),
            (r"\btruncate\b", 12),
            (r"\balter\s+table\b", 12),
            (r"\bcreate\s+(table|database|index)\b", 10),
            # SELECT * FROM pattern (direct table dump — always suspicious)
            (r"\bselect\b\s+\*\s+\bfrom\b", 14),
            # SELECT col FROM table (no WHERE — dump attempt)
            (r"\bselect\b\s+\S+\s+\bfrom\b\s+\w+\s*(?:--|;|$)", 13),

            # 8. Basic Keywords & Operators
            (r"\bselect\b", 2),
            (r"\bfrom\b", 1),
            (r"\bwhere\b", 1),
            (r"\bdrop\b", 8),
            (r"\bexec\b\s*\(|xp_", 13),
            
            # 9. Stacked Queries & Comments
            (r";(?:\s*(?:select|insert|update|delete|drop|create|alter))", 13),
            (r"['\";|]", 2),
            (r"--(?:\s|$)", 5),
            (r"/\*!", 9),
            (r"\*\/\s*;", 9),
            (r"\(\s*select\b", 12),
            (r"(?:select|union)\s*\(\s*select", 14),
            
            # 10. XPath & NoSQL Injection
            (r"\bxpath\b", 10),
            (r"\bextractvalue\s*\(", 12),
            (r"\bupdatexml\s*\(", 12),
            (r"\bdb\.\w+\.find\b", 11),
            (r"{\s*['\"]?\$where['\"]?\s*:", 13),
            (r"\bfind\s*\(\s*{.*}.*\)", 10),

            # 11. NoSQL Injection (MongoDB-style operators)
            (r"\$(?:where|or|and|ne|gt|lt|gte|lte|in|nin|exists|regex|elemMatch)\b", 14),
            (r"\bdb\.\w+\.(?:insert|update|remove|findOne|aggregate|mapReduce)\s*\(", 14),
            (r"['\"],\s*\$(?:or|and|where)\s*:", 16),
            (r"\$or\s*:\s*\[", 15),

            # 12. JavaScript time-based blind (MongoDB/NoSQL)
            (r"var\s+\w+\s*=\s*new\s+Date\s*\(\s*\)", 14),
            (r"do\s*\{[^}]*\}\s*while\s*\(", 13),
            (r"curDate\s*-\s*date\s*<\s*\d+", 14),

            # 13. MySQL/MariaDB JSON Functions (SQLi via JSON)
            (r"\bjson_extract\s*\(", 13),
            (r"\bjson_depth\s*\(", 13),
            (r"\bjson_value\s*\(", 13),
            (r"\bjson_contains\s*\(", 13),
        ]

    def get_score(self, input_string: str) -> int:
        if not input_string:
            return 0

        # *** ส่งผ่าน normalizer ก่อน เพื่อถอด obfuscation ***
        normalized = recursive_normalize(input_string)

        total_score = 0
        matched_patterns = []
        
        for pattern, score in self.rules:
            matches = re.findall(pattern, normalized, re.IGNORECASE | re.DOTALL)
            if matches:
                occurrence_bonus = (len(matches) - 1) * 2
                pattern_score = score + max(0, occurrence_bonus)
                total_score += pattern_score
                matched_patterns.append((pattern[:40], pattern_score, len(matches)))

        # --- Contextual checks ---
        
        # Quote imbalance (stronger indicator)
        single_quotes = normalized.count("'")
        double_quotes = normalized.count('"')
        if single_quotes % 2 != 0 or double_quotes % 2 != 0:
            total_score += 6

        # Stacked queries (very strong indicator)
        if re.search(
            r";\s*\b(select|insert|update|drop|delete|set|create|alter)\b",
            normalized,
            re.IGNORECASE | re.DOTALL,
        ):
            total_score += 14

        # Multiple SQL operators in sequence
        operator_count = len(re.findall(r"\b(union|select|from|where|and|or|insert|update|delete|drop)\b", normalized, re.IGNORECASE))
        if operator_count >= 4:
            total_score += 8

        # Mixed quotes with operators = likely injection
        if re.search(r"['\"].*(?:union|select|insert|update|delete|drop).*['\"]", normalized, re.IGNORECASE | re.DOTALL):
            total_score += 10

        # CASE WHEN with numeric comparison (boolean-based SQLi)
        if re.search(r"\bcase\s+when.*\d+\s*=\s*\d+", normalized, re.IGNORECASE | re.DOTALL):
            total_score += 12

        return total_score

    def is_sqli(self, input_string: str, threshold: int | None = None) -> bool:
        score = self.get_score(input_string)
        limit = threshold if threshold is not None else self.threshold
        return score >= limit

    def analyze(self, input_string: str, threshold: int | None = None) -> dict:
        """Full analysis — คืน dict พร้อม score, verdict, และ normalized string."""
        score = self.get_score(input_string)
        limit = threshold if threshold is not None else self.threshold
        return {
            "is_sqli": score >= limit,
            "score": score,
            "threshold": limit,
            "normalized": recursive_normalize(input_string),
        }