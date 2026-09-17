"""
traffic_generator/normal_traffic.py — Simulates legitimate user traffic

Spawns N threads each sending HTTP requests at a normal rate.
All requests go to the FastAPI /api/traffic endpoint.
"""

import threading
import time
import random
import requests
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))
import config

NORMAL_IPS = [f"192.168.1.{i}" for i in range(1, 31)]
PROTOCOLS  = ["HTTP", "HTTPS"]
USER_AGENTS = ["Mozilla/5.0", "Chrome/120", "Safari/17", "Firefox/121"]


def send_normal_request(stop_event: threading.Event):
    session = requests.Session()
    while not stop_event.is_set():
        ip = random.choice(NORMAL_IPS)
        try:
            session.post(config.TARGET_URL, json={
                "src_ip":      ip,
                "dst_ip":      "127.0.0.1",
                "src_port":    random.randint(1024, 65535),
                "dst_port":    8000,
                "protocol":    random.choice(PROTOCOLS),
                "packet_size": random.randint(200, 900),
                "payload_size": random.randint(100, 500),
                "syn_flag":    False,
            }, timeout=2)
        except Exception:
            pass
        time.sleep(random.uniform(0.03, 0.2))


def start_normal_traffic(thread_count: int = 5, stop_event: threading.Event = None):
    if stop_event is None:
        stop_event = threading.Event()
    threads = []
    for _ in range(thread_count):
        t = threading.Thread(target=send_normal_request, args=(stop_event,), daemon=True)
        t.start()
        threads.append(t)
    print(f"[Normal] Started {thread_count} threads sending normal traffic to {config.TARGET_URL}")
    return stop_event, threads


if __name__ == "__main__":
    stop = threading.Event()
    _, threads = start_normal_traffic(thread_count=config.NORMAL_THREAD_COUNT, stop_event=stop)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[Normal] Stopping...")
        stop.set()
