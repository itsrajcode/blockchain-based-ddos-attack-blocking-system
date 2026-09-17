"""
database/queries.py — CRUD helper functions
"""

import sqlite3
from datetime import datetime
from typing import Optional
from .db import get_connection


# ─── Traffic Log ─────────────────────────────────────────────────────────────

def insert_traffic_log(data: dict):
    conn = get_connection()
    conn.execute(
        """INSERT INTO traffic_log
           (timestamp, src_ip, protocol, packets_per_sec, bytes_per_sec,
            connection_count, syn_ratio, severity, action)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            data.get("timestamp", datetime.utcnow().isoformat()),
            data["src_ip"],
            data.get("protocol", "HTTP"),
            data.get("packets_per_sec", 0),
            data.get("bytes_per_sec", 0),
            data.get("connection_count", 0),
            data.get("syn_ratio", 0),
            data.get("severity", "NORMAL"),
            data.get("action", "ALLOW"),
        ),
    )
    conn.commit()
    conn.close()


def get_traffic_stats() -> dict:
    conn = get_connection()
    row = conn.execute("""
        SELECT
            COUNT(*)                                    AS total,
            SUM(CASE WHEN severity='NORMAL' THEN 1 ELSE 0 END) AS normal_count,
            SUM(CASE WHEN severity!='NORMAL' THEN 1 ELSE 0 END) AS suspicious_count
        FROM traffic_log
    """).fetchone()
    conn.close()
    return dict(row) if row else {}


# ─── Attack Events ────────────────────────────────────────────────────────────

def insert_attack_event(data: dict):
    conn = get_connection()
    conn.execute(
        """INSERT OR IGNORE INTO attack_events
           (attack_id, timestamp, src_ip, attack_type, severity,
            packets_per_sec, confidence, detection_method,
            blockchain_hash, block_index, status)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            data["attack_id"],
            data.get("timestamp", datetime.utcnow().isoformat()),
            data["src_ip"],
            data.get("attack_type", "Unknown"),
            data.get("severity", "HIGH"),
            data.get("packets_per_sec", 0),
            data.get("confidence", 0),
            data.get("detection_method", "rules"),
            data.get("blockchain_hash"),
            data.get("block_index", -1),
            data.get("status", "DETECTED"),
        ),
    )
    conn.commit()
    conn.close()


def update_attack_blockchain(attack_id: str, block_hash: str, block_index: int):
    conn = get_connection()
    conn.execute(
        "UPDATE attack_events SET blockchain_hash=?, block_index=?, status='BLOCKED' WHERE attack_id=?",
        (block_hash, block_index, attack_id),
    )
    conn.commit()
    conn.close()


def get_recent_attacks(limit: int = 20) -> list:
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM attack_events ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_attack_count() -> int:
    conn = get_connection()
    count = conn.execute("SELECT COUNT(*) FROM attack_events").fetchone()[0]
    conn.close()
    return count


# ─── Blocked IPs ──────────────────────────────────────────────────────────────

def insert_blocked_ip(data: dict):
    conn = get_connection()
    conn.execute(
        """INSERT OR REPLACE INTO blocked_ips
           (ip, reason, attack_type, severity, blocked_at, expires_at, attack_id)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            data["ip"],
            data.get("reason", "DDoS Attack"),
            data.get("attack_type", "Unknown"),
            data.get("severity", "HIGH"),
            data.get("blocked_at", datetime.utcnow().isoformat()),
            data.get("expires_at"),
            data.get("attack_id"),
        ),
    )
    conn.commit()
    conn.close()


def remove_blocked_ip(ip: str):
    conn = get_connection()
    conn.execute("DELETE FROM blocked_ips WHERE ip=?", (ip,))
    conn.commit()
    conn.close()


def get_blocked_ips() -> list:
    conn = get_connection()
    rows = conn.execute("SELECT * FROM blocked_ips ORDER BY blocked_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_blocked_ip_count() -> int:
    conn = get_connection()
    count = conn.execute("SELECT COUNT(*) FROM blocked_ips").fetchone()[0]
    conn.close()
    return count
