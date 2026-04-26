import re
from .normalizer import recursive_normalize
from .sqli_detector import SQLDetector
from .xss_detector import XSSDetector

BLOCK_THRESHOLD = 15

sql_engine = SQLDetector()
xss_engine = XSSDetector()

_DEFINITE_SQL_INDICATORS = re.compile(
    r"\b(union\s+select|information_schema|sleep\s*\(|benchmark\s*\("
    r"|waitfor\s+delay|extractvalue\s*\(|updatexml\s*\(|into\s+(outfile|dumpfile)"
    r"|load_file\s*\()\b",
    re.IGNORECASE,
)

_RAW_SQL_COMMENT = re.compile(r"--|/\*|#\s*$", re.MULTILINE)

_HEX_IN_SQL_CONTEXT = re.compile(
    r"(?:['\"]|=\s*)0x[0-9a-f]{2,}|0x[0-9a-f]{2,}(?:\s*(?:or|and|union|--))",
    re.IGNORECASE,
)

_XSS_DANGEROUS_CONTEXT = re.compile(
    r"(?:eval|alert|prompt|confirm|setTimeout|setInterval)\s*\(|"
    r"<script|javascript:|on\w+\s*=",
    re.IGNORECASE,
)

_STRONG_SQLI_PATTERNS = re.compile(
    r"\b(union\s+select|select\s+\*\s+from\s+\w|drop\s+table|drop\s+database"
    r"|insert\s+into\s+\w+\s*\(|delete\s+from\s+\w+|update\s+\w+\s+set\s+\w+\s*="
    r"|having\s+\d+=\d+|order\s+by\s+\d+|group\s+by\s+\d+"
    r"|waitfor\s+delay|exec\s*\(|xp_cmdshell)\b",
    re.IGNORECASE,
)

_SQL_INJECTION_OPERATOR = re.compile(
    r"=\s*['\"]|\bwhere\s+\w+\s*=|'\s*(or|and)\s+['\"]?\w",
    re.IGNORECASE,
)

_TAUTOLOGY_PATTERN = re.compile(
    r"['\"]?\s*(?:or|and)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?",
    re.IGNORECASE,
)


def _is_likely_natural_language(text: str, normalized: str = None) -> bool:
    """
    v6: Check both raw AND normalized - if normalized reveals SQL, it's an attack
    """
    # If normalized reveals SQL attack patterns → not NL
    if normalized:
        if _DEFINITE_SQL_INDICATORS.search(normalized):
            return False
        if _STRONG_SQLI_PATTERNS.search(normalized):
            return False
        if _TAUTOLOGY_PATTERN.search(normalized):
            return False

    # Rule 1 — definite SQL indicators
    if _DEFINITE_SQL_INDICATORS.search(text):
        return False

    # Rule 2 — SQL comment
    if _RAW_SQL_COMMENT.search(text):
        return False

    # Rule 3 — Strong SQL structural syntax
    if _STRONG_SQLI_PATTERNS.search(text):
        return False

    # Rule 3b — Tautology pattern
    if _TAUTOLOGY_PATTERN.search(text):
        return False

    # Rule 4 — single apostrophe → likely possessive
    if text.count("'") == 1:
        return True

    if text.count("'") % 2 != 0:
        if not _SQL_INJECTION_OPERATOR.search(text):
            return True

    # Rule 5 — INSERT without proper SQL syntax
    # ยกเว้น: NoSQL pattern เช่น db.col.insert({...}) ต้องถือว่าเป็น attack
    if re.search(r"\binsert\b", text, re.IGNORECASE):
        if re.search(r"\bdb\.\w+\.insert\s*\(", text, re.IGNORECASE):
            return False  # NoSQL insert = suspicious
        if not re.search(r"\binsert\s+into\s+\w+\s*\(", text, re.IGNORECASE):
            return True

    # Rule 6 — DROP without object keyword
    if re.search(r"\bdrop\b", text, re.IGNORECASE):
        if not re.search(
            r"\bdrop\s+(table|database|schema|index|view|procedure|trigger)\b",
            text, re.IGNORECASE,
        ):
            return True

    # Rule 7 — "select X from Y" without injection operator
    # BUT: "select * from table" or "select col from table" is always suspicious (dump pattern)
    if re.search(r"\bselect\b.*\bfrom\b", text, re.IGNORECASE):
        # Direct table dump patterns — never treat as natural language
        if re.search(r"\bselect\b\s*[\*\w,\s]+\s*\bfrom\b\s+\w+", text, re.IGNORECASE):
            return False
        if not _SQL_INJECTION_OPERATOR.search(text):
            return True

    # Rule 8 — "update X set Y" without assignment
    if re.search(r"\bupdate\b.*\bset\b", text, re.IGNORECASE):
        if not re.search(r"\bset\s+\w+\s*=", text, re.IGNORECASE):
            return True

    return False


def _is_natural_hex(text: str) -> bool:
    if not re.search(r"0x[0-9a-f]{2,}", text, re.IGNORECASE):
        return False
    return not _HEX_IN_SQL_CONTEXT.search(text)


def _is_natural_function_call(text: str) -> bool:
    if not re.search(r"function\s*\(", text, re.IGNORECASE):
        return False
    return not _XSS_DANGEROUS_CONTEXT.search(text)


def _was_obfuscated(raw: str, normalized: str) -> bool:
    """Detect if payload used obfuscation (hex, url-encode, comments, entities)"""
    raw_lower = raw.lower().strip()
    # Meaningful normalization change = obfuscation
    if normalized != raw_lower:
        return True
    # Explicit obfuscation markers in raw
    if re.search(r"0x[0-9a-f]{4,}", raw, re.IGNORECASE):
        return True
    if re.search(r"%[0-9a-f]{2}", raw, re.IGNORECASE):
        return True
    # Double URL encoding: %25xx (%25 = encoded %)
    if re.search(r"%25[0-9a-f]{2}", raw, re.IGNORECASE):
        return True
    if re.search(r"/\*.*?\*/", raw, re.IGNORECASE):
        return True
    if re.search(r"&#x?[0-9a-f]+;?", raw, re.IGNORECASE):
        return True
    return False


def scan_payload(raw_payload: str) -> dict:
    """
    Main WAF scan function.
    v7: No score reduction when obfuscation detected.
        NL check uses normalized text too.
    """
    if not raw_payload or not isinstance(raw_payload, str):
        return {
            "is_blocked": False,
            "total_score": 0,
            "attack_type": None,
            "cleaned_payload": "",
        }

    normalized_data = recursive_normalize(raw_payload)

    sqli_score: int = sql_engine.get_score(normalized_data)
    xss_score_val, xss_triggered = xss_engine.get_score(normalized_data)

    # Obfuscation detection — if attacker encoded the payload, never reduce score
    obfuscated = _was_obfuscated(raw_payload, normalized_data)

    # If normalized text itself is a tautology/injection, always treat as obfuscated
    if not obfuscated and _TAUTOLOGY_PATTERN.search(normalized_data):
        obfuscated = True
    if not obfuscated and _DEFINITE_SQL_INDICATORS.search(normalized_data):
        obfuscated = True

    if not obfuscated:
        is_natural_lang = _is_likely_natural_language(raw_payload, normalized_data)

        if is_natural_lang:
            if sqli_score < 20:
                sqli_score = max(0, sqli_score - 12)
            elif sqli_score < 30:
                sqli_score = max(0, sqli_score - 8)

        # Very short 2-word input likely safe
        if sqli_score < 12 and re.search(r"^\w+\s+\w+$", raw_payload):
            sqli_score = max(0, sqli_score - 8)

        # Hex in non-SQL context
        if _is_natural_hex(raw_payload) and sqli_score < 15:
            sqli_score = max(0, sqli_score - 10)

        # Pure function() documentation
        if _is_natural_function_call(raw_payload) and xss_score_val < 20:
            xss_score_val = max(0, xss_score_val - 15)

    total_score = sqli_score + xss_score_val

    attack_types = []
    if sqli_score > 0:
        attack_types.append("SQL Injection")
    if xss_score_val > 0:
        attack_types.append("XSS")
    attack_type = ", ".join(attack_types) if attack_types else None

    return {
        "is_blocked": total_score >= BLOCK_THRESHOLD,
        "total_score": total_score,
        "attack_type": attack_type,
        "cleaned_payload": normalized_data,
        "details": {
            "sqli_score": sqli_score,
            "xss_score": xss_score_val,
            "xss_rules": xss_triggered,
        },
    }