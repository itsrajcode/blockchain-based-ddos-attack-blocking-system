"""
ml/dataset_generator.py — Generates synthetic training data for the DDoS classifier

Produces a CSV with labelled normal and attack traffic feature vectors.
Run: python ml/dataset_generator.py
"""

import csv
import random
import os

OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "training_data.csv")

COLUMNS = [
    "packet_count", "total_bytes", "avg_packet_size",
    "packets_per_sec", "bytes_per_sec", "connection_count",
    "syn_count", "syn_ratio", "dst_port", "flow_duration", "label"
]


def rand(lo, hi, decimals=2):
    return round(random.uniform(lo, hi), decimals)


def generate_normal(n=1500):
    rows = []
    for _ in range(n):
        pkt = random.randint(5, 150)
        size = pkt * random.randint(200, 900)
        dur = rand(1, 10)
        pps = round(pkt / dur, 2)
        bps = round(size / dur, 2)
        syn = random.randint(0, int(pkt * 0.1))
        rows.append([
            pkt, size, round(size / max(pkt, 1), 2),
            pps, bps,
            random.randint(1, 15),
            syn, round(syn / max(pkt, 1), 4),
            random.choice([80, 443, 8000, 8080]),
            dur, 0,
        ])
    return rows


def generate_http_flood(n=1000):
    rows = []
    for _ in range(n):
        pkt = random.randint(3000, 8000)
        size = pkt * random.randint(400, 700)
        dur = rand(0.5, 2)
        pps = round(pkt / dur, 2)
        bps = round(size / dur, 2)
        rows.append([
            pkt, size, round(size / max(pkt, 1), 2),
            pps, bps,
            random.randint(400, 900),
            random.randint(0, 10),
            round(random.uniform(0.0, 0.05), 4),
            random.choice([80, 443, 8000]),
            dur, 1,
        ])
    return rows


def generate_syn_flood(n=1000):
    rows = []
    for _ in range(n):
        pkt = random.randint(2000, 6000)
        size = pkt * random.randint(60, 100)   # SYN packets are tiny
        dur = rand(0.3, 1.5)
        pps = round(pkt / dur, 2)
        bps = round(size / dur, 2)
        syn = int(pkt * rand(0.8, 1.0))
        rows.append([
            pkt, size, round(size / max(pkt, 1), 2),
            pps, bps,
            random.randint(500, 1200),
            syn, round(syn / max(pkt, 1), 4),
            random.choice([80, 443, 22, 8000]),
            dur, 1,
        ])
    return rows


def generate_udp_flood(n=1000):
    rows = []
    for _ in range(n):
        pkt = random.randint(4000, 10000)
        size = pkt * random.randint(300, 1400)
        dur = rand(0.5, 2)
        pps = round(pkt / dur, 2)
        bps = round(size / dur, 2)
        rows.append([
            pkt, size, round(size / max(pkt, 1), 2),
            pps, bps,
            random.randint(100, 300),
            0, 0.0,
            random.randint(1, 65535),
            dur, 1,
        ])
    return rows


def generate_slowloris(n=500):
    """Slow, low-packet-rate attack that opens many connections."""
    rows = []
    for _ in range(n):
        pkt = random.randint(5, 50)
        size = pkt * random.randint(100, 300)
        dur = rand(20, 120)
        pps = round(pkt / dur, 2)
        bps = round(size / dur, 2)
        rows.append([
            pkt, size, round(size / max(pkt, 1), 2),
            pps, bps,
            random.randint(200, 800),   # many open connections
            random.randint(0, 5),
            round(random.uniform(0.0, 0.1), 4),
            random.choice([80, 443, 8000]),
            dur, 1,
        ])
    return rows


def generate():
    all_rows = (
        generate_normal()
        + generate_http_flood()
        + generate_syn_flood()
        + generate_udp_flood()
        + generate_slowloris()
    )
    random.shuffle(all_rows)

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(COLUMNS)
        writer.writerows(all_rows)

    total = len(all_rows)
    attacks = sum(1 for r in all_rows if r[-1] == 1)
    print(f"Generated {total} samples ({total - attacks} normal, {attacks} attack)")
    print(f"Saved to: {OUTPUT_PATH}")


if __name__ == "__main__":
    generate()
