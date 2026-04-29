import urllib.parse
import html
import base64
import re
import unicodedata
import binascii


def is_mostly_text(s):
    if not s:
        return False
    printable_count = sum(1 for c in s if c.isprintable() or c.isspace())
    ratio = printable_count / len(s)
    return ratio > 0.9


def is_base64(s):
    if not s or len(s) < 8:  
        return False

    
    s2 = s.strip().replace("-", "+").replace("_", "/")
    padding = (4 - len(s2) % 4) % 4
    s2 += "=" * padding

   
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", s2):
        return False

    if len(s2) < 12:
        return False

    try:
        decoded = base64.b64decode(s2, validate=True)
        decoded_str = decoded.decode("utf-8", errors="strict")
        return is_mostly_text(decoded_str)
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return False


def _try_base64_decode(s):
    s2 = s.strip().replace("-", "+").replace("_", "/")
    padding = (4 - len(s2) % 4) % 4
    s2 += "=" * padding
    try:
        decoded = base64.b64decode(s2, validate=True)
        result = decoded.decode("utf-8", errors="strict")
        if result and is_mostly_text(result):
            return result
    except Exception:
        pass
    return None


def _decode_sql_hex(text: str) -> str:
    def replace_hex(m):
        try:
            return bytes.fromhex(m.group(1)).decode("latin-1")
        except Exception:
            return m.group(0)
    return re.sub(r"0x([0-9a-fA-F]+)", replace_hex, text)


def recursive_normalize(text, max_depth=5):
    if not isinstance(text, str) or not text:
        return ""

    current_text = unicodedata.normalize("NFKC", text)

    hex_decoded = _decode_sql_hex(current_text)
    if hex_decoded != current_text:
        current_text = hex_decoded

    for _ in range(max_depth):
        prev = current_text

        current_text = urllib.parse.unquote(current_text)

        current_text = html.unescape(current_text)

        current_text = re.sub(
            r"&#x([0-9a-fA-F]+);?",
            lambda m: chr(int(m.group(1), 16)),
            current_text,
            flags=re.IGNORECASE,
        )
        current_text = re.sub(
            r"&#([0-9]+);?",
            lambda m: chr(int(m.group(1))),
            current_text,
        )

        if "\\" in current_text:
            try:
                decoded_unicode = current_text.encode("utf-8").decode("unicode_escape")
                if is_mostly_text(decoded_unicode):
                    current_text = decoded_unicode
            except Exception:
                pass

        if len(current_text) >= 8 and is_base64(current_text):
            decoded = _try_base64_decode(current_text)
            if decoded:
                current_text = decoded

        if current_text == prev:
            break

    clean_text = current_text.lower()

    clean_text = re.sub(r"/\*!\d*(.*?)\*/", r"\1", clean_text, flags=re.DOTALL)

    clean_text = re.sub(r"/\*.*?\*/", "", clean_text, flags=re.DOTALL)

    clean_text = re.sub(r"--.*$", "", clean_text, flags=re.MULTILINE)
    clean_text = re.sub(r"#.*$", "", clean_text, flags=re.MULTILINE)

    clean_text = re.sub(r"\s+", " ", clean_text).strip()

    return clean_text



if __name__ == "__main__":
    print("--- Advanced WAF Normalizer Test ---")

    tests = [
        ("Unicode Escape", r"\u003cscript\u003ealert(1)\u003c/script\u003e"),
        ("MySQL Wrap", "/*!50000 SELECT*/ * FROM users"),
        ("Mixed URL+Comment", "SELECT%20/*foo*/%20*%20FROM%20users"),
        (
            "Base64 no-padding",
            "PGJvZHkgb25sb2FkPWFsZXJ0KCd0ZXN0MScpPg",
        ),  # <body onload=alert('test1')>
        (
            "Base64 with-padding",
            "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        ),  # <script>alert(1)</script>
        ("URL-safe Base64", "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg"), 
    ]

    for name, payload in tests:
        print(f"\n[{name}]\n  IN : {payload}\n  OUT: {recursive_normalize(payload)}")
