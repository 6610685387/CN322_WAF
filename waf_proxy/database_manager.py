from sqlalchemy import create_engine, Column, Integer, String, DateTime, MetaData, Table, ForeignKey, func
from sqlalchemy.orm import sessionmaker, declarative_base
from datetime import datetime, timedelta, timezone
import os

# Use DATABASE_URL from environment variables, default to a local SQLite for initial setup if not found
DATABASE_URL = "postgresql://postgres:Cnplanner%40123456789@db.hswrzwcegmghgeixfkor.supabase.co:5432/postgres?sslmode=require"
print(f"🔥 DATABASE_URL = {DATABASE_URL}")                                                                                    # In a real scenario with docker-compose, DATABASE_URL should be set to connect to the postgres service.

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class AttackLog(Base):
    __tablename__ = "attack_logs"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, index=True)
    payload = Column(String)
    attack_type = Column(String, index=True)
    score = Column(Integer)
    path = Column(String) # Add this line
    timestamp = Column(DateTime, default=datetime.utcnow)

class BannedIP(Base):
    __tablename__ = "banned_ips"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, index=True, unique=True)
    reason = Column(String, nullable=True)
    ban_timestamp = Column(DateTime, default=datetime.utcnow)

# Function to initialize the database (create tables if they don't exist)
def init_db():
    Base.metadata.create_all(bind=engine)

# Function to add a new attack log
def add_log(ip_address: str, payload: str, attack_type: str, score: int, path: str = ""): # Update signature
    db = SessionLocal()
    try:
        log_entry = AttackLog(
            ip_address=ip_address,
            payload=payload,
            attack_type=attack_type,
            score=score,
            path=path, # Add this line
            timestamp=datetime.now(timezone.utc)
        )
        db.add(log_entry)
        db.commit()
        db.refresh(log_entry)
        return log_entry
    except Exception as e:
        db.rollback()
        print(f"Error adding log: {e}") # Log the error
        return None
    finally:
        db.close()

# Function to get all logs
def get_all_logs():
    db = SessionLocal()
    try:
        logs = db.query(AttackLog).order_by(AttackLog.timestamp.desc()).all()
        results = [
            {
                "timestamp": log.timestamp.isoformat(),
                "ip_address": log.ip_address,
                "attack_type": log.attack_type,
                "score": log.score,
                "payload": log.payload,
                "path": log.path
            }
            for log in logs
        ]
        return results
    except Exception as e:
        print(f"Error getting all logs: {e}")
        return []
    finally:
        db.close()

# Function to check if an IP is banned
def is_ip_banned(ip_address: str) -> bool:
    db = SessionLocal()
    try:
        is_banned = db.query(BannedIP).filter(BannedIP.ip_address == ip_address).first() is not None
        return is_banned
    except Exception as e:
        print(f"Error checking ban status: {e}")
        return False
    finally:
        db.close()

# Function to ban an IP address

def ban_ip(ip_address: str, reason: str = None):
    db = SessionLocal()
    try:
        # ✅ เช็คใน session เดียวกัน
        existing = db.query(BannedIP).filter(BannedIP.ip_address == ip_address).first()

        if existing:
            print(f"IP {ip_address} already banned")
            return None

        ban_entry = BannedIP(
            ip_address=ip_address,
            reason=reason,
            ban_timestamp=datetime.now(timezone.utc)
        )

        db.add(ban_entry)
        db.commit()
        db.refresh(ban_entry)

        return ban_entry

    except Exception as e:
        db.rollback()
        print(f"Error banning IP: {e}")
        return None
    finally:
        db.close()

# Function to unban an IP address
def unban_ip(ip_address: str):
    db = SessionLocal()
    try:
        ban_entry = db.query(BannedIP).filter(BannedIP.ip_address == ip_address).first()

        if ban_entry:
            db.delete(ban_entry)
            db.commit()   # ✅ ต้อง commit
            print(f"Unbanned {ip_address}")
            return True

        return False

    except Exception as e:
        db.rollback()
        print(f"Error unbanning IP: {e}")
        return False
    finally:
        db.close()

# Function to get attack statistics for the dashboard
def get_attack_stats():
    db = SessionLocal()
    try:
        # Example: Get total attacks, attacks by type, and count of banned IPs
        total_attacks = db.query(AttackLog).count()
        attacks_by_type = db.query(AttackLog.attack_type, func.count(AttackLog.id)).group_by(AttackLog.attack_type).all()
        banned_ips_count = db.query(BannedIP).count()
        
        # Get recent attack counts (e.g., last 24 hours) for time-series graph
        recent_attacks = db.query(AttackLog).filter(AttackLog.timestamp >= datetime.utcnow() - timedelta(hours=24)).count()

        stats = {
            "total_attacks": total_attacks,
            "attacks_by_type": dict(attacks_by_type),
            "banned_ips_count": banned_ips_count,
            "recent_attacks_24h": recent_attacks # Placeholder for time-series data
        }
        return stats
    except Exception as e:
        print(f"Error getting attack stats: {e}")
        return {}
    finally:
        db.close()

# NEW FUNCTION: Function to get all banned IPs
def get_banned_ips():
    db = SessionLocal()
    try:
        banned_ips = db.query(BannedIP).all()
        # Format data for JSON serialization
        results = [
            {
                "ip": ip.ip_address,
                "reason": ip.reason,
                "ban_timestamp": ip.ban_timestamp.isoformat() if ip.ban_timestamp else None
            }
            for ip in banned_ips
        ]
        return results
    except Exception as e:
        print(f"Error getting banned IPs: {e}")
        return []
    finally:
        db.close()


# Helper to run initialization when the module is imported or run
if __name__ == "__main__":
    print("Initializing database...")
    init_db()
    print("Database initialized.")

    # Example usage (for testing the module directly)
    print("--- Testing Database Manager ---")
    
    # Add some sample logs
    print("Adding sample logs...")
    add_log("192.168.1.100", "<script>alert('XSS')</script>", "XSS", 85)
    add_log("192.168.1.101", "' OR '1'='1", "SQLi", 90)
    add_log("192.168.1.100", "UNION SELECT user, password FROM users", "SQLi", 95)
    
    # Ban an IP
    print("Banning IP 192.168.1.100 for XSS...")
    ban_ip("192.168.1.100", "Repeated XSS attempts")
    
    # Check ban status
    print(f"Is 192.168.1.100 banned? {is_ip_banned('192.168.1.100')}")
    print(f"Is 192.168.1.101 banned? {is_ip_banned('192.168.1.101')}")
    
    # Get stats
    print("Getting attack statistics:")
    stats = get_attack_stats()
    print(stats)

    # Test get_banned_ips
    print("Getting banned IPs list:")
    banned_list = get_banned_ips()
    print(banned_list)
    
    # Unban an IP
    print("Unbanning IP 192.168.1.100...")
    unban_ip("192.168.1.100")
    print(f"Is 192.168.1.100 banned after unban? {is_ip_banned('192.168.1.100')}")
    print("--- Test Complete ---")
