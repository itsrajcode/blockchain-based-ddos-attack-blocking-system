# Blockchain-Based DDoS Attack Detection and Prevention System

A full-stack academic prototype that simulates DDoS traffic, detects attacks using rule-based + ML (Random Forest) detection, records verified attack events on a simulated blockchain ledger, enforces IP blocking, and visualises everything on a premium real-time dashboard.

---

## Architecture

```
Traffic Generator (Python threads)
         ↓  POST /api/traffic
   FastAPI Backend (localhost:8000)
         ↓
  Traffic Monitor  →  Feature Extractor
         ↓
  DDoS Detection Engine
  (Rule-based + Random Forest ML)
         ↙                 ↘
      NORMAL              ATTACK
         ↓                   ↓
      ALLOW          Decision Engine
                            ↓
                   Blockchain Ledger (3-node SHA-256 PoW)
                            ↓
                   Blocking Engine (IP blocklist)
                            ↓
                   SQLite Audit Trail
                            ↓
              WebSocket → Real-time Dashboard
```

---

## Project Structure

```
modest-newton/
├── backend/
│   ├── main.py                  # FastAPI app + WebSocket
│   ├── config.py                # All thresholds & settings
│   ├── models/schemas.py        # Pydantic models
│   ├── modules/
│   │   ├── traffic_monitor.py   # Sliding-window per-IP stats
│   │   ├── feature_extractor.py # Raw stats → feature vectors
│   │   ├── detector.py          # Rule-based + ML detection
│   │   ├── blockchain.py        # SHA-256 PoW blockchain (3 nodes)
│   │   ├── decision_engine.py   # Severity → action mapping
│   │   └── blocking_engine.py   # IP blocklist with auto-expiry
│   ├── database/
│   │   ├── db.py                # SQLite schema init
│   │   └── queries.py           # CRUD helpers
│   ├── ml/
│   │   ├── dataset_generator.py # Synthetic training data
│   │   ├── train.py             # Train Random Forest
│   │   └── model.pkl            # Saved model (after training)
│   └── requirements.txt
├── traffic_generator/
│   ├── normal_traffic.py        # Simulates normal users
│   ├── attack_traffic.py        # HTTP/SYN/UDP flood simulation
│   └── orchestrator.py          # CLI controller
├── dashboard/
│   ├── index.html               # Real-time security dashboard
│   ├── style.css                # Dark glassmorphism UI
│   └── app.js                   # WebSocket + Chart.js client
└── README.md
```

---

## Quick Start

### 1. Install Dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 2. Train the ML Model

```bash
cd backend
python ml/train.py
```

This generates synthetic training data and trains a Random Forest classifier. Expect ~99% accuracy on synthetic data.

### 3. Start the Backend

```bash
cd backend
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### 4. Open the Dashboard

Open `dashboard/index.html` in your browser, **or** visit:

```
http://localhost:8000/dashboard
```

### 5. Generate Traffic (Choose one)

**Option A — Use the dashboard simulation buttons** (easiest):
- Click **Normal Traffic** to start safe traffic
- Click **Launch Attack** to start a DDoS simulation
- Watch the dashboard update in real-time!

**Option B — Use the CLI orchestrator:**

```bash
# Normal traffic (60s)
cd traffic_generator
python orchestrator.py --mode normal --duration 60

# HTTP flood attack (30s)
python orchestrator.py --mode attack --attack-type http_flood --duration 30

# SYN flood attack (30s)
python orchestrator.py --mode attack --attack-type syn_flood --duration 30

# UDP flood attack (30s)
python orchestrator.py --mode attack --attack-type udp_flood --duration 30

# Mixed (normal + attack simultaneously)
python orchestrator.py --mode mixed --duration 60
```

---

## REST API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/traffic` | Ingest a traffic packet |
| `GET` | `/api/stats` | Current dashboard statistics |
| `GET` | `/api/attacks?limit=20` | Recent attack events |
| `GET` | `/api/blockchain` | Full blockchain ledger |
| `GET` | `/api/blockchain/verify` | Verify chain integrity |
| `GET` | `/api/blocked` | Currently blocked IPs |
| `DELETE` | `/api/blocked/{ip}` | Manually unblock an IP |
| `POST` | `/api/simulate` | Trigger built-in simulation |
| `WS` | `/ws` | WebSocket: real-time stats stream |

---

## Detection Thresholds

Configurable in `backend/config.py`:

| Metric | LOW | MEDIUM | HIGH |
|--------|-----|--------|------|
| Packets/sec | 100 | 500 | 1,000 |
| Connections | 20 | 50 | 100 |
| Bytes/sec | — | — | 500,000 |
| SYN ratio | — | — | 0.75 |

---

## Blockchain Design

- **Algorithm:** SHA-256 Proof-of-Work
- **Difficulty:** 2 leading zeros (configurable)
- **Nodes:** 3 security nodes (node-A, node-B, node-C)
- **Primary node** (node-A) mines blocks after attack detection
- **Peer nodes** (node-B, node-C) verify hash chain before appending
- **On-chain data:** Attack ID, timestamp, source IP, attack type, severity, confidence, PoW nonce
- **Off-chain data:** Raw packets, full traffic logs (SQLite)

---

## Severity → Action Map

| Severity | Trigger Condition | Action |
|----------|-------------------|--------|
| NORMAL | pps < 100 | ALLOW |
| LOW | pps 100–499 | MONITOR |
| MEDIUM | pps 500–999 | RATE_LIMIT |
| HIGH | pps ≥ 1000 or SYN ratio ≥ 0.75 | BLOCK + Blockchain |

---

## Research Evaluation Metrics

Run the backend, generate traffic, then evaluate:

```bash
# Check detection accuracy (from training output)
python backend/ml/train.py

# Verify blockchain integrity
curl http://localhost:8000/api/blockchain/verify

# Count attacks vs blocked
curl http://localhost:8000/api/stats
```

Key metrics to report:
- **Detection Accuracy** (from ML training report)
- **False Positive Rate** (NORMAL traffic misclassified as attack)
- **Detection Latency** (time from packet receipt to block decision)
- **Blockchain Transaction Latency** (mining time per block)
- **System Throughput** (requests/sec the backend can handle)

---

## Technology Stack

| Layer | Technology |
|-------|------------|
| Backend API | Python 3.10+ + FastAPI |
| Real-time | WebSockets (FastAPI native) |
| Detection | scikit-learn Random Forest |
| Blockchain | Pure Python SHA-256 PoW chain |
| Database | SQLite (built-in) |
| Dashboard | Vanilla HTML + CSS + JavaScript |
| Charts | Chart.js 4.x |
| Traffic Gen | Python requests + threading |
