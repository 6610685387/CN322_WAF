from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    DateTime,
    MetaData,
    Table,
    ForeignKey,
    func,
)
from sqlalchemy.orm import sessionmaker, declarative_base
from datetime import datetime, timedelta, timezone
from threading import Thread
import queue
import os

DATABASE_URL = "postgresql://postgres.hswrzwcegmghgeixfkor:Cnplanner%40123456789@aws-1-ap-northeast-1.pooler.supabase.com:6543/postgres"
print(f"🔥 DATABASE_URL = {DATABASE_URL}")

engine = create_engine(
    DATABASE_URL,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# ============================================================
# Models
# ============================================================


class AttackLog(Base):
    __tablename__ = "attack_logs"
    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, index=True)
    payload = Column(String)
    attack_type = Column(String, index=True)
    score = Column(Integer)
    path = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)


class BannedIP(Base):
    __tablename__ = "banned_ips"
    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, index=True, unique=True)
    reason = Column(String, nullable=True)
    ban_timestamp = Column(DateTime, default=datetime.utcnow)


_ban_cache: set[str] = set()
_cache_loaded = False


def _load_ban_cache():
    """โหลด banned IPs ทั้งหมดเข้า memory ครั้งเดียวตอน startup"""
    global _ban_cache, _cache_loaded
    db = SessionLocal()
    try:
        rows = db.query(BannedIP.ip_address).all()
        _ban_cache = {r.ip_address for r in rows}
        print(f"✅ Ban cache loaded: {len(_ban_cache)} IPs")
    except Exception as e:
        print(f"⚠️ Error loading ban cache (fail-open): {e}")
    finally:
        _cache_loaded = True
        db.close()


def is_ip_banned(ip_address: str) -> bool:
    """ตรวจสอบจาก in-memory cache — O(1) ไม่แตะ DB"""
    global _cache_loaded
    if not _cache_loaded:
        _load_ban_cache()
    return ip_address in _ban_cache




_log_queue: queue.Queue = queue.Queue(maxsize=1000)


def _log_worker():
    """Background thread — drain queue แล้ว batch insert"""
    while True:
        batch = []
        try:
            
            item = _log_queue.get(timeout=2)
            batch.append(item)
            
            while not _log_queue.empty() and len(batch) < 50:
                batch.append(_log_queue.get_nowait())
        except queue.Empty:
            continue

        db = SessionLocal()
        try:
            db.bulk_insert_mappings(AttackLog, batch)
            db.commit()
        except Exception as e:
            db.rollback()
            print(f"Error batch inserting logs: {e}")
        finally:
            db.close()



_worker_thread = Thread(target=_log_worker, daemon=True)
_worker_thread.start()



def init_db():
    Base.metadata.create_all(bind=engine)
    _load_ban_cache()


def add_log(
    ip_address: str, payload: str, attack_type: str, score: int, path: str = ""
):
    """Non-blocking — push to queue แล้ว return ทันที"""
    try:
        _log_queue.put_nowait(
            {
                "ip_address": ip_address,
                "payload": payload,
                "attack_type": attack_type,
                "score": score,
                "path": path,
                "timestamp": datetime.now(timezone.utc),
            }
        )
    except queue.Full:
        print("⚠️ Log queue full — dropping log entry")


def get_all_logs(limit: int = 20):
    db = SessionLocal()
    try:
        logs = (
            db.query(AttackLog).order_by(AttackLog.timestamp.desc()).limit(limit).all()
        )
        return [
            {
                "timestamp": log.timestamp.isoformat(),
                "ip_address": log.ip_address,
                "attack_type": log.attack_type,
                "score": log.score,
                "payload": log.payload,
                "path": log.path,
            }
            for log in logs
        ]
    except Exception as e:
        print(f"Error getting all logs: {e}")
        return []
    finally:
        db.close()


def ban_ip(ip_address: str, reason: str = None):
    db = SessionLocal()
    try:
        existing = db.query(BannedIP).filter(BannedIP.ip_address == ip_address).first()
        if existing:
            print(f"IP {ip_address} already banned")
            return None
        ban_entry = BannedIP(
            ip_address=ip_address,
            reason=reason,
            ban_timestamp=datetime.now(timezone.utc),
        )
        db.add(ban_entry)
        db.commit()
        db.refresh(ban_entry)
        _ban_cache.add(ip_address)  
        return ban_entry
    except Exception as e:
        db.rollback()
        print(f"Error banning IP: {e}")
        return None
    finally:
        db.close()


def unban_ip(ip_address: str):
    db = SessionLocal()
    try:
        ban_entry = db.query(BannedIP).filter(BannedIP.ip_address == ip_address).first()
        if ban_entry:
            db.delete(ban_entry)
            db.commit()
            _ban_cache.discard(ip_address) 
            print(f"Unbanned {ip_address}")
            return True
        return False
    except Exception as e:
        db.rollback()
        print(f"Error unbanning IP: {e}")
        return False
    finally:
        db.close()


def get_attack_stats():
    db = SessionLocal()
    try:
        total_attacks = db.query(AttackLog).count()
        attacks_by_type = (
            db.query(AttackLog.attack_type, func.count(AttackLog.id))
            .group_by(AttackLog.attack_type)
            .all()
        )
        banned_ips_count = db.query(BannedIP).count()
        recent_attacks = (
            db.query(AttackLog)
            .filter(AttackLog.timestamp >= datetime.utcnow() - timedelta(hours=24))
            .count()
        )
        return {
            "total_attacks": total_attacks,
            "attacks_by_type": dict(attacks_by_type),
            "banned_ips_count": banned_ips_count,
            "recent_attacks_24h": recent_attacks,
        }
    except Exception as e:
        print(f"Error getting attack stats: {e}")
        return {}
    finally:
        db.close()


def get_banned_ips():
    db = SessionLocal()
    try:
        banned_ips = db.query(BannedIP).all()
        return [
            {
                "ip": ip.ip_address,
                "reason": ip.reason,
                "ban_timestamp": (
                    ip.ban_timestamp.isoformat() if ip.ban_timestamp else None
                ),
            }
            for ip in banned_ips
        ]
    except Exception as e:
        print(f"Error getting banned IPs: {e}")
        return []
    finally:
        db.close()


if __name__ == "__main__":
    print("Initializing database...")
    init_db()
    print("Database initialized.")
