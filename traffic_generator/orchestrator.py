"""
traffic_generator/orchestrator.py — CLI tool to control traffic scenarios

Usage:
  python orchestrator.py --mode normal --duration 60
  python orchestrator.py --mode attack --attack-type syn_flood --duration 30
  python orchestrator.py --mode mixed --duration 60
"""

import argparse
import threading
import time
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from normal_traffic import start_normal_traffic
from attack_traffic import start_attack


def run(mode: str, duration: int, attack_type: str):
    stop_events = []

    if mode in ("normal", "mixed"):
        stop, _ = start_normal_traffic(thread_count=5)
        stop_events.append(stop)

    if mode in ("attack", "mixed"):
        stop, _ = start_attack(attack_type=attack_type)
        stop_events.append(stop)

    print(f"\n[Orchestrator] Mode: {mode.upper()} | Duration: {duration}s | Type: {attack_type}")
    print("[Orchestrator] Press Ctrl+C to stop early.\n")

    try:
        for remaining in range(duration, 0, -1):
            print(f"\r[Orchestrator] Running... {remaining:3d}s remaining", end="", flush=True)
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[Orchestrator] Interrupted by user.")
    finally:
        for se in stop_events:
            se.set()
        time.sleep(0.5)
        print("\n[Orchestrator] All threads stopped.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DDoS Traffic Orchestrator")
    parser.add_argument(
        "--mode", choices=["normal", "attack", "mixed"], default="normal",
        help="Traffic mode: normal | attack | mixed"
    )
    parser.add_argument(
        "--duration", type=int, default=60,
        help="Duration in seconds (default: 60)"
    )
    parser.add_argument(
        "--attack-type", dest="attack_type",
        choices=["http_flood", "syn_flood", "udp_flood"], default="http_flood",
        help="Type of attack traffic"
    )
    args = parser.parse_args()
    run(args.mode, args.duration, args.attack_type)
