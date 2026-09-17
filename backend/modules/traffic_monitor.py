"""
modules/traffic_monitor.py — Sliding-window per-IP traffic aggregator

Runs as a background task alongside the FastAPI server.
All incoming traffic packets are fed via record_packet().
Every MONITOR_WINDOW_SECONDS, stats are aggregated and emitted.
"""

import asyncio
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, Deque, Callable, List, Awaitable
import threading


class IPStats:
    """Per-IP sliding window statistics."""

    def __init__(self, window: float):
        self.window = window
        self._lock = threading.Lock()
        self.timestamps: Deque[float] = deque()
        self.byte_sizes: Deque[int] = deque()
        self.packet_sizes: Deque[int] = deque()
        self.syn_timestamps: Deque[float] = deque()
        self.connection_set: set = set()
        self.protocol: str = "HTTP"
        self.dst_port: int = 8000
        self.first_seen: float = time.time()

    def add_packet(self, packet_size: int, byte_size: int, syn: bool,
                   src_port: int, protocol: str, dst_port: int):
        now = time.time()
        with self._lock:
            self.timestamps.append(now)
            self.byte_sizes.append(byte_size)
            self.packet_sizes.append(packet_size)
            if syn:
                self.syn_timestamps.append(now)
            self.connection_set.add(src_port)
            self.protocol = protocol
            self.dst_port = dst_port
            self._prune(now)

    def _prune(self, now: float):
        cutoff = now - self.window
        while self.timestamps and self.timestamps[0] < cutoff:
            self.timestamps.popleft()
            self.byte_sizes.popleft()
            self.packet_sizes.popleft()
        while self.syn_timestamps and self.syn_timestamps[0] < cutoff:
            self.syn_timestamps.popleft()

    def snapshot(self) -> dict:
        now = time.time()
        with self._lock:
            self._prune(now)
            count = len(self.timestamps)
            total_bytes = sum(self.byte_sizes)
            syn_count = len(self.syn_timestamps)
            duration = max(now - self.first_seen, 0.001)
            actual_window = min(self.window, duration)
            pps = count / actual_window if actual_window > 0 else 0
            bps = total_bytes / actual_window if actual_window > 0 else 0
            avg_pkt = (sum(self.packet_sizes) / count) if count > 0 else 0
            syn_ratio = (syn_count / count) if count > 0 else 0
            conn_count = len(self.connection_set)

        return {
            "packet_count": count,
            "total_bytes": total_bytes,
            "avg_packet_size": round(avg_pkt, 2),
            "packets_per_sec": round(pps, 2),
            "bytes_per_sec": round(bps, 2),
            "connection_count": conn_count,
            "syn_count": syn_count,
            "syn_ratio": round(syn_ratio, 4),
            "flow_duration": round(duration, 3),
            "protocol": self.protocol,
            "dst_port": self.dst_port,
        }


class TrafficMonitor:
    """
    Central monitor. Call record_packet() for every incoming packet.
    Subscribers receive aggregated snapshots via register_callback().
    """

    def __init__(self, window_seconds: float = 5.0):
        self.window = window_seconds
        self._ip_stats: Dict[str, IPStats] = defaultdict(lambda: IPStats(window_seconds))
        self._lock = threading.Lock()
        self._callbacks: List[Callable[[str, dict], Awaitable[None]]] = []
        self._total_requests = 0
        self._normal_count = 0
        self._suspicious_count = 0
        # History for chart (last 60 points)
        self.pps_history: Deque[float] = deque(maxlen=60)
        self.attack_rate_history: Deque[float] = deque(maxlen=60)

    def record_packet(self, src_ip: str, packet_size: int = 512,
                      byte_size: int = 512, syn: bool = False,
                      src_port: int = 0, protocol: str = "HTTP",
                      dst_port: int = 8000):
        with self._lock:
            self._ip_stats[src_ip].add_packet(
                packet_size, byte_size, syn, src_port, protocol, dst_port
            )
            self._total_requests += 1

    def increment_severity(self, is_attack: bool):
        with self._lock:
            if is_attack:
                self._suspicious_count += 1
            else:
                self._normal_count += 1

    def get_snapshot(self, src_ip: str) -> dict:
        with self._lock:
            if src_ip not in self._ip_stats:
                return {}
            snap = self._ip_stats[src_ip].snapshot()
            snap["src_ip"] = src_ip
            return snap

    def get_all_snapshots(self) -> List[dict]:
        with self._lock:
            ips = list(self._ip_stats.keys())
        result = []
        for ip in ips:
            snap = self.get_snapshot(ip)
            if snap:
                result.append(snap)
        return result

    def get_counters(self) -> dict:
        with self._lock:
            return {
                "total_requests": self._total_requests,
                "normal_count": self._normal_count,
                "suspicious_count": self._suspicious_count,
            }

    def add_pps_history(self, pps: float, attack_rate: float):
        self.pps_history.append(round(pps, 1))
        self.attack_rate_history.append(round(attack_rate, 1))

    def register_callback(self, cb: Callable[[str, dict], Awaitable[None]]):
        self._callbacks.append(cb)

    async def dispatch(self, src_ip: str, snapshot: dict):
        for cb in self._callbacks:
            await cb(src_ip, snapshot)


# Singleton instance shared across the application
monitor = TrafficMonitor()
