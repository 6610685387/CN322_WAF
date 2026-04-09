import urllib.parse
import html
import base64
import re
import unicodedata
import binascii

def is_mostly_text(s):
    """ตรวจสอบว่าข้อความเป็นตัวอักษรที่อ่านออกจริงหรือไม่ (รวม Whitespace)"""
    if not s:
        return False
    printable_count = sum(1 for c in s if c.isprintable() or c.isspace())
    ratio = printable_count / len(s)
    return ratio > 0.9

def is_base64(s):
    """ตรวจสอบรูปแบบ Base64"""
    if not s or len(s) % 4 != 0:
        return False
    if not re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', s):
        return False
    try:
        base64.b64decode(s, validate=True)
        return True
    except (binascii.Error, ValueError):
        return False

def recursive_normalize(text, max_depth=5):
    """
    ระบบถอดรหัสซ้อนหลายชั้น (Advanced WAF Normalization)
    ครอบคลุม: URL, HTML, Base64, Unicode Escape และ MySQL Obfuscation
    """
    if not isinstance(text, str) or not text:
        return ""

    # 1. Unicode Normalization (NFKC) กันตัวอักษรหน้าตาคล้ายกัน
    current_text = unicodedata.normalize("NFKC", text)

    for _ in range(max_depth):
        prev = current_text

        # 2. URL Decoding (%27 -> ')
        current_text = urllib.parse.unquote(current_text)

        # 3. HTML Entity Decoding (&lt; -> <)
        current_text = html.unescape(current_text)

        # 4. Unicode Escape Decoding (\u0027 -> ')
        if "\\" in current_text:
            try:
                # ใช้ codecs.decode หรือการ encode/decode เพื่อแก้รหัส \u หรือ \x
                # 'unicode_escape' จะจัดการทั้ง \uXXXX และ \xXX
                decoded_unicode = current_text.encode('utf-8').decode('unicode_escape')
                if is_mostly_text(decoded_unicode):
                    current_text = decoded_unicode
            except Exception:
                pass

        # 5. Base64 Decoding (ถอดรหัสเมื่อเข้าเงื่อนไข)
        if len(current_text) > 4 and is_base64(current_text):
            try:
                decoded_bytes = base64.b64decode(current_text)
                try:
                    decoded_str = decoded_bytes.decode('utf-8', errors='strict')
                    if decoded_str and is_mostly_text(decoded_str):
                        current_text = decoded_str
                except UnicodeDecodeError:
                    pass
            except Exception:
                pass

        if current_text == prev:
            break

    # --- 6. Final Cleanup (MySQL & SQL Obfuscation) ---
    clean_text = current_text.lower()

    # Unwrap MySQL Executable Comments: /*!50000 SELECT */ -> SELECT 
    # (ต้องทำก่อนลบคอมเมนต์ปกติ)
    clean_text = re.sub(r'/\*!\d*(.*?)\*/', r'\1', clean_text, flags=re.DOTALL)
    
    # ลบคอมเมนต์แบบ Block: /* ... */
    clean_text = re.sub(r'/\*.*?\*/', '', clean_text, flags=re.DOTALL)
    
    # ลบคอมเมนต์แบบ Line: -- หรือ #
    clean_text = re.sub(r'--.*$', '', clean_text, flags=re.MULTILINE)
    clean_text = re.sub(r'#.*$', '', clean_text, flags=re.MULTILINE)
    
    # ยุบช่องว่างให้เหลือช่องเดียว เพื่อกันการใช้ช่องว่างเลี่ยง Regex (เช่น SEL   ECT)
    clean_text = re.sub(r'\s+', ' ', clean_text).strip()

    return clean_text

# --- Test Suite ---
if __name__ == "__main__":
    print("--- Advanced WAF Normalizer Test ---")
    
    # ทดสอบ Unicode Escape
    t1 = r"\u003cscript\u003ealert(1)\u003c/script\u003e"
    print(f"Test 1 (Unicode Escape): {t1} \n=> {recursive_normalize(t1)}")

    # ทดสอบ MySQL Executable Comment
    t2 = "/*!50000 SELECT*/ * FROM users"
    print(f"\nTest 2 (MySQL Wrap): {t2} \n=> {recursive_normalize(t2)}")

    # ทดสอบ Mixed Obfuscation (URL + Comment)
    t3 = "SELECT%20/*foo*/%20*%20FROM%20users"
    print(f"\nTest 3 (Mixed): {t3} \n=> {recursive_normalize(t3)}")