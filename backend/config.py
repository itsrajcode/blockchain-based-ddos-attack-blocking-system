# config.py — Central configuration for the DDoS Detection System

import os

# ─── Server ──────────────────────────────────────────────────────────────────
HOST = "0.0.0.0"
PORT = 8000

# ─── Detection Thresholds (Rule-based) ───────────────────────────────────────
THRESHOLDS = {
    "packets_per_sec_low":    100,
    "packets_per_sec_medium": 500,
    "packets_per_sec_high":   1000,
    "connection_count_low":   20,
    "connection_count_medium": 50,
    "connection_count_high":  100,
    "bytes_per_sec_high":     500_000,
    "syn_ratio_high":         0.75,
}

# ─── Blocking ─────────────────────────────────────────────────────────────────
BLOCK_DURATION_SECONDS = 300        # Auto-unblock after 5 minutes
RATE_LIMIT_WINDOW_SECONDS = 60      # Rate limit window

# ─── Traffic Monitor ──────────────────────────────────────────────────────────
MONITOR_WINDOW_SECONDS = 5          # Sliding window size for aggregation
STATS_BROADCAST_INTERVAL = 0.5      # WebSocket push interval (seconds)

# ─── Blockchain ───────────────────────────────────────────────────────────────
BLOCKCHAIN_NODES = ["node-A", "node-B", "node-C"]
MINING_DIFFICULTY = 2               # PoW: hash must start with this many zeros

# ─── ML Model ─────────────────────────────────────────────────────────────────
MODEL_PATH = os.path.join(os.path.dirname(__file__), "ml", "model.pkl")
ML_CONFIDENCE_THRESHOLD = 0.65      # Min confidence to trust ML decision

# ─── Database ─────────────────────────────────────────────────────────────────
DB_PATH = os.path.join(os.path.dirname(__file__), "ddos_system.db")

# ─── Traffic Generator (used by generator scripts) ────────────────────────────
TARGET_URL = f"http://localhost:{PORT}/api/traffic"
NORMAL_THREAD_COUNT = 5
ATTACK_THREAD_COUNT = 50
NORMAL_RATE_PER_THREAD = 0.05       # seconds between requests (20/s per thread)
