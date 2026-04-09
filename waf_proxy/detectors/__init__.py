from .normalizer import recursive_normalize
from .sqli_detector import SQLDetector
from .xss_detector import XSSDetector

# --- Configuration ---
# กำหนดคะแนนขั้นต่ำที่จะทำการบล็อก (Threshold)
# เช่น ถ้าคะแนนรวม >= 10 ให้ถือว่าเป็นการโจมตี
BLOCK_THRESHOLD = 10

# สร้าง Instance ของ Detector ไว้ล่วงหน้า (Singleton) เพื่อประหยัด CPU 
# ไม่ต้องสร้างใหม่ทุกครั้งที่มี Request เข้ามา
sql_engine = SQLDetector()
xss_engine = XSSDetector()

def scan_payload(raw_payload):
    """
    ฟังก์ชันหลักสำหรับตรวจสอบ Payload
    รับค่า: raw_payload (string)
    ส่งคืน: dict ที่ระบุผลการตรวจจับ คะแนน และประเภทการโจมตี
    """
    if not raw_payload or not isinstance(raw_payload, str):
        return {
            "is_blocked": False,
            "total_score": 0,
            "attack_type": None,
            "cleaned_payload": ""
        }

    # 1. ทำความสะอาดข้อมูล (Normalization) ขั้นสูง
    normalized_data = recursive_normalize(raw_payload)

    # 2. ส่งข้อมูลที่ล้างแล้วไปตรวจหา SQL Injection
    # (หมายเหตุ: ไฟล์ sqli_detector.py ของคุณต้องมีฟังก์ชัน get_score หรือเปลี่ยนชื่อให้ตรงกัน)
    sqli_score = sql_engine.get_score(normalized_data)

    # 3. ส่งข้อมูลที่ล้างแล้วไปตรวจหา XSS
    # (หมายเหตุ: ไฟล์ xss_detector.py ของคุณต้องมีฟังก์ชัน get_score)
    xss_score = xss_engine.get_score(normalized_data)

    # 4. รวมคะแนน
    total_score = sqli_score + xss_score

    # 5. ตัดสินใจเลือกประเภทการโจมตีหลัก (เพื่อเอาไปลง Log)
    attack_types = []

    if sqli_score > 0:
        attack_types.append("SQL Injection")
    if xss_score > 0:
        attack_types.append("XSS")
    attack_type = ", ".join(attack_types) if attack_types else None

    return {
        "is_blocked": total_score >= BLOCK_THRESHOLD,
        "total_score": total_score,
        "attack_type": attack_type,
        "cleaned_payload": normalized_data,
        "details": {
            "sqli_score": sqli_score,
            "xss_score": xss_score
        }
    }