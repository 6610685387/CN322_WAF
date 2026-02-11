import sqlite3
from database import DB_NAME

def log_attack(ip, attack_type, payload, path):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO attack_logs (ip_address, attack_type, payload, path)
        VALUES (?, ?, ?, ?)
    """, (ip, attack_type, payload, path))

    conn.commit()
    conn.close()
