"""
database/db.py — SQLite connection and schema initialization
"""

import sqlite3
import sys
import os

# Allow imports from backend root
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import config


def get_connection() -> sqlite3.Connection:
    """Return a thread-safe SQLite connection."""
    conn = sqlite3.connect(config.DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """Create all tables if they don't exist."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS traffic_log (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT    NOT NULL,
            src_ip          TEXT    NOT NULL,
            protocol        TEXT    DEFAULT 'HTTP',
            packets_per_sec REAL    DEFAULT 0,
            bytes_per_sec   REAL    DEFAULT 0,
            connection_count INTEGER DEFAULT 0,
            syn_ratio       REAL    DEFAULT 0,
            severity        TEXT    DEFAULT 'NORMAL',
            action          TEXT    DEFAULT 'ALLOW'
        );

        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip          TEXT    PRIMARY KEY,
            reason      TEXT,
            attack_type TEXT,
            severity    TEXT,
            blocked_at  TEXT    NOT NULL,
            expires_at  TEXT,
            attack_id   TEXT
        );

        CREATE TABLE IF NOT EXISTS attack_events (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            attack_id        TEXT    UNIQUE NOT NULL,
            timestamp        TEXT    NOT NULL,
            src_ip           TEXT    NOT NULL,
            attack_type      TEXT    NOT NULL,
            severity         TEXT    NOT NULL,
            packets_per_sec  REAL    DEFAULT 0,
            confidence       REAL    DEFAULT 0,
            detection_method TEXT    DEFAULT 'rules',
            blockchain_hash  TEXT,
            block_index      INTEGER DEFAULT -1,
            status           TEXT    DEFAULT 'DETECTED'
        );

        CREATE INDEX IF NOT EXISTS idx_traffic_log_ip ON traffic_log(src_ip);
        CREATE INDEX IF NOT EXISTS idx_traffic_log_ts ON traffic_log(timestamp);
        CREATE INDEX IF NOT EXISTS idx_attacks_ts     ON attack_events(timestamp);
    """)

    conn.commit()
    conn.close()
