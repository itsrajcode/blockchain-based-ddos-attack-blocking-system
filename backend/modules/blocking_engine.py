"""
modules/blocking_engine.py — IP blocklist manager with auto-expiry
"""

import os
import sys
import threading
from datetime import datetime, timedelta, timezone
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import config

# Lazy import to avoid circular imports
def _get_db_queries():
    from database import queries
    return queries


class BlockingEngine:
    def __init__(self):
        self._lock = threading.Lock()
        # { ip: expires_at_timestamp (float) or None for permanent }
        self._blocked: dict = {}
        self._load_from_db()

    def _load_from_db(self):
        """Restore persisted blocks on startup."""
        try:
            queries = _get_db_queries()
            rows = queries.get_blocked_ips()
            now = datetime.now(timezone.utc)
            for row in rows:
                expires_str = row.get("expires_at")
                if expires_str:
                    try:
                        exp = datetime.fromisoformat(expires_str.replace("Z", "+00:00"))
                        if exp > now:
                            self._blocked[row["ip"]] = exp.timestamp()
                        else:
                            queries.remove_blocked_ip(row["ip"])
                    except Exception:
                        pass
                else:
                    self._blocked[row["ip"]] = None
        except Exception as e:
            print(f"[Blocker] Could not load persisted blocks: {e}")

    def block_ip(self, ip: str, reason: str = "DDoS Attack",
                 attack_type: str = "Unknown", severity: str = "HIGH",
                 attack_id: Optional[str] = None,
                 duration_seconds: Optional[int] = None) -> bool:
        """Block an IP. Returns True if newly blocked, False if already blocked."""
        with self._lock:
            if ip in self._blocked:
                return False

            duration = duration_seconds or config.BLOCK_DURATION_SECONDS
            now = datetime.now(timezone.utc)
            expires_at = now + timedelta(seconds=duration)
            self._blocked[ip] = expires_at.timestamp()

        # Persist to DB
        try:
            queries = _get_db_queries()
            queries.insert_blocked_ip({
                "ip":         ip,
                "reason":     reason,
                "attack_type": attack_type,
                "severity":   severity,
                "blocked_at": now.isoformat(),
                "expires_at": expires_at.isoformat(),
                "attack_id":  attack_id,
            })
        except Exception as e:
            print(f"[Blocker] DB error: {e}")

        print(f"[Blocker] 🚫 Blocked {ip} for {duration}s — {attack_type}")
        return True

    def unblock_ip(self, ip: str):
        with self._lock:
            self._blocked.pop(ip, None)
        try:
            _get_db_queries().remove_blocked_ip(ip)
        except Exception:
            pass

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            if ip not in self._blocked:
                return False
            exp = self._blocked[ip]
            if exp is None:
                return True
            if datetime.now(timezone.utc).timestamp() > exp:
                # Auto-expire
                del self._blocked[ip]
                return False
            return True

    def get_blocked_list(self) -> list:
        """Return currently active blocked IPs (pruning expired entries)."""
        try:
            return _get_db_queries().get_blocked_ips()
        except Exception:
            return []

    def get_blocked_count(self) -> int:
        with self._lock:
            now_ts = datetime.now(timezone.utc).timestamp()
            return sum(
                1 for exp in self._blocked.values()
                if exp is None or exp > now_ts
            )


# Singleton
blocker = BlockingEngine()
