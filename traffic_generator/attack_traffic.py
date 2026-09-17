"""
traffic_generator/attack_traffic.py — Simulates DDoS attack traffic

Three attack modes:
  http_flood  — Mass concurrent HTTP requests from one IP
  syn_flood   — TCP SYN packets (simulated via HTTP with syn_flag=True)
  udp_flood   — High-volume UDP-style packets via HTTP

All attacks originate from distinct attacker IP ranges for easy identification.
"""

import threading
import time
import random
import requests
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))
import config

ATTACK_IPS = [f"10.0.0.{i}" for i in range(1, 21)]


def _http_flood_worker(attacker_ip: str, stop_event: threading.Event):
    """Send maximum-rate HTTP requests — simulates HTTP flood."""
    session = requests.Session()
    while not stop_event.is_set():
        try:
            session.post(config.TARGET_URL, json={
                "src_ip":      attacker_ip,
                "dst_ip":      "127.0.0.1",
                "src_port":    random.randint(1024, 65535),
                "dst_port":    8000,
                "protocol":    "HTTP",
                "packet_size": random.randint(60, 200),
                "payload_size": random.randint(50, 100),
                "syn_flag":    False,
            }, timeout=1)
        except Exception:
            pass
        # No sleep — maximum rate


def _syn_flood_worker(attacker_ip: str, stop_event: threading.Event):
    """Simulate SYN flood — many half-open connections."""
    session = requests.Session()
    while not stop_event.is_set():
        try:
            session.post(config.TARGET_URL, json={
                "src_ip":      attacker_ip,
                "dst_ip":      "127.0.0.1",
                "src_port":    random.randint(1024, 65535),
                "dst_port":    random.choice([80, 443, 8000]),
                "protocol":    "TCP",
                "packet_size": random.randint(40, 64),   # SYN packets are small
                "payload_size": 0,
                "syn_flag":    True,
            }, timeout=1)
        except Exception:
            pass


def _udp_flood_worker(attacker_ip: str, stop_event: threading.Event):
    """Simulate UDP flood — massive byte throughput."""
    session = requests.Session()
    while not stop_event.is_set():
        try:
            session.post(config.TARGET_URL, json={
                "src_ip":      attacker_ip,
                "dst_ip":      "127.0.0.1",
                "src_port":    random.randint(1, 65535),
                "dst_port":    random.randint(1, 65535),
                "protocol":    "UDP",
                "packet_size": random.randint(512, 1400),
                "payload_size": random.randint(400, 1300),
                "syn_flag":    False,
            }, timeout=1)
        except Exception:
            pass


ATTACK_WORKERS = {
    "http_flood": _http_flood_worker,
    "syn_flood":  _syn_flood_worker,
    "udp_flood":  _udp_flood_worker,
}


def start_attack(attack_type: str = "http_flood",
                 thread_count: int = None,
                 stop_event: threading.Event = None) -> tuple:
    """
    Launch an attack simulation.
    Returns (stop_event, threads).
    Call stop_event.set() to terminate.
    """
    thread_count = thread_count or config.ATTACK_THREAD_COUNT
    if stop_event is None:
        stop_event = threading.Event()

    worker_fn = ATTACK_WORKERS.get(attack_type, _http_flood_worker)
    attacker_ip = random.choice(ATTACK_IPS)

    threads = []
    for _ in range(thread_count):
        t = threading.Thread(
            target=worker_fn, args=(attacker_ip, stop_event), daemon=True
        )
        t.start()
        threads.append(t)

    print(f"[Attack] 🚨 {attack_type.upper()} launched: {attacker_ip} → {thread_count} threads")
    return stop_event, threads


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--type", default="http_flood", choices=list(ATTACK_WORKERS.keys()))
    parser.add_argument("--threads", type=int, default=config.ATTACK_THREAD_COUNT)
    args = parser.parse_args()

    stop = threading.Event()
    start_attack(args.type, args.threads, stop)
    print("[Attack] Press Ctrl+C to stop")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[Attack] Stopping attack...")
        stop.set()
