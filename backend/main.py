"""
main.py — FastAPI application: REST API + WebSocket hub
"""

import asyncio
import json
import os
import sys
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Set

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

# ─── Path setup ───────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(__file__))

import config
from database.db import init_db
from database import queries
from models.schemas import TrafficPacket, SimulateRequest
from modules.traffic_monitor import monitor
from modules.feature_extractor import extract_features
from modules.detector import detect
from modules.decision_engine import decide
from modules.blockchain import blockchain
from modules.blocking_engine import blocker


# ─── WebSocket Manager ────────────────────────────────────────────────────────

class ConnectionManager:
    def __init__(self):
        self.active: Set[WebSocket] = set()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.add(ws)

    def disconnect(self, ws: WebSocket):
        self.active.discard(ws)

    async def broadcast(self, payload: dict):
        dead = set()
        msg = json.dumps(payload)
        for ws in self.active:
            try:
                await ws.send_text(msg)
            except Exception:
                dead.add(ws)
        self.active -= dead


ws_manager = ConnectionManager()


# ─── Background stats broadcaster ─────────────────────────────────────────────

async def _stats_broadcaster():
    """Push live stats to all connected dashboards every 500ms."""
    while True:
        try:
            counters = monitor.get_counters()
            total_pps = sum(
                s.get("packets_per_sec", 0) for s in monitor.get_all_snapshots()
            )
            attack_pps = sum(
                s.get("packets_per_sec", 0)
                for s in monitor.get_all_snapshots()
                if s.get("packets_per_sec", 0) > config.THRESHOLDS["packets_per_sec_low"]
            )
            monitor.add_pps_history(total_pps, attack_pps)

            verify_result = blockchain.verify()
            payload = {
                "type": "stats",
                "data": {
                    "total_requests":        counters["total_requests"],
                    "normal_count":          counters["normal_count"],
                    "suspicious_count":      counters["suspicious_count"],
                    "attack_count":          queries.get_attack_count(),
                    "blocked_ip_count":      blocker.get_blocked_count(),
                    "blockchain_record_count": blockchain.get_block_count(),
                    "system_status":         _get_system_status(),
                    "active_attacks":        queries.get_recent_attacks(5),
                    "pps_history":           list(monitor.pps_history),
                    "attack_rate_history":   list(monitor.attack_rate_history),
                    "chain_valid":           verify_result["valid"],
                    "node_status":           blockchain.get_node_status(),
                },
            }
            await ws_manager.broadcast(payload)
        except Exception as e:
            pass  # Don't crash the broadcaster
        await asyncio.sleep(config.STATS_BROADCAST_INTERVAL)


def _get_system_status() -> str:
    if blocker.get_blocked_count() > 0:
        recent = queries.get_recent_attacks(1)
        if recent:
            ts = recent[0].get("timestamp", "")
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                age = (datetime.now(timezone.utc) - dt).total_seconds()
                if age < 30:
                    return "UNDER_ATTACK"
            except Exception:
                pass
        return "ALERT"
    return "PROTECTED"


# ─── Lifespan ─────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    print("[System] Database initialised.")
    print(f"[System] ML model path: {config.MODEL_PATH}")
    task = asyncio.create_task(_stats_broadcaster())
    yield
    task.cancel()


# ─── App ──────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="DDoS Detection System API",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Middleware: Block known IPs ───────────────────────────────────────────────

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

class BlocklistMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Allow dashboard and internal paths
        if request.url.path.startswith(("/ws", "/dashboard", "/api/blocked", "/api/blockchain", "/api/stats", "/docs", "/openapi")):
            return await call_next(request)
        client_ip = request.headers.get("X-Forwarded-For", request.client.host if request.client else "unknown")
        src_ip = client_ip.split(",")[0].strip()
        if blocker.is_blocked(src_ip):
            return JSONResponse(
                status_code=403,
                content={"detail": f"Access denied: {src_ip} is blocked due to suspicious activity."}
            )
        return await call_next(request)

app.add_middleware(BlocklistMiddleware)


# ─── Pipeline helper ──────────────────────────────────────────────────────────

async def _run_pipeline(src_ip: str, packet: TrafficPacket) -> dict:
    """Full detection pipeline for one packet."""
    # 1. Record in monitor
    monitor.record_packet(
        src_ip=src_ip,
        packet_size=packet.packet_size,
        byte_size=packet.packet_size + packet.payload_size,
        syn=packet.syn_flag,
        src_port=packet.src_port,
        protocol=packet.protocol,
        dst_port=packet.dst_port,
    )

    # 2. Get current stats snapshot
    snapshot = monitor.get_snapshot(src_ip)
    if not snapshot:
        return {"action": "ALLOW", "severity": "NORMAL"}

    # 3. Feature extraction
    fv = extract_features(src_ip, snapshot)

    # 4. Detection
    result = detect(fv)

    # 5. Decision
    decision = decide(result)

    # 6. Update counters
    monitor.increment_severity(result.is_attack)

    # 7. Log traffic
    queries.insert_traffic_log({
        "src_ip":          src_ip,
        "protocol":        packet.protocol,
        "packets_per_sec": fv.packets_per_sec,
        "bytes_per_sec":   fv.bytes_per_sec,
        "connection_count": fv.connection_count,
        "syn_ratio":       fv.syn_ratio,
        "severity":        result.severity,
        "action":          result.action,
    })

    # 8. Block + Blockchain if attack
    if decision["should_block"]:
        attack_id = f"DDOS-{uuid.uuid4().hex[:8].upper()}"

        # Blockchain record
        bc_record = {
            "attack_id":        attack_id,
            "timestamp":        datetime.now(timezone.utc).isoformat(),
            "src_ip":           src_ip,
            "attack_type":      result.attack_type,
            "packets_per_sec":  fv.packets_per_sec,
            "severity":         result.severity,
            "confidence":       result.confidence,
            "detection_method": result.detection_method,
            "detection_node":   "node-A",
            "action_taken":     "BLOCKED",
        }
        bc_info = blockchain.add_attack(bc_record)

        # Block the IP
        is_new = blocker.block_ip(
            ip=src_ip,
            reason=f"{result.attack_type} detected",
            attack_type=result.attack_type,
            severity=result.severity,
            attack_id=attack_id,
        )

        if is_new:
            # Persist attack event
            queries.insert_attack_event({
                "attack_id":        attack_id,
                "src_ip":           src_ip,
                "attack_type":      result.attack_type,
                "severity":         result.severity,
                "packets_per_sec":  fv.packets_per_sec,
                "confidence":       result.confidence,
                "detection_method": result.detection_method,
                "blockchain_hash":  bc_info["hash"],
                "block_index":      bc_info["index"],
                "status":           "BLOCKED",
            })

            # Broadcast alert to dashboard
            await ws_manager.broadcast({
                "type": "attack_alert",
                "data": {
                    "attack_id":   attack_id,
                    "src_ip":      src_ip,
                    "attack_type": result.attack_type,
                    "severity":    result.severity,
                    "pps":         fv.packets_per_sec,
                    "bc_hash":     bc_info["hash"],
                    "bc_index":    bc_info["index"],
                    "timestamp":   datetime.now(timezone.utc).isoformat(),
                },
            })

    return decision


# ─── REST Endpoints ───────────────────────────────────────────────────────────

@app.get("/")
async def root():
    return {"status": "DDoS Detection System Backend is running", "version": "1.0.0"}


@app.post("/api/traffic")
async def receive_traffic(packet: TrafficPacket, request: Request):
    """Main ingestion endpoint — receives packets from traffic generator."""
    src_ip = packet.src_ip or (request.client.host if request.client else "0.0.0.0")
    decision = await _run_pipeline(src_ip, packet)
    return decision


@app.get("/api/stats")
async def get_stats():
    counters = monitor.get_counters()
    return {
        **counters,
        "attack_count":          queries.get_attack_count(),
        "blocked_ip_count":      blocker.get_blocked_count(),
        "blockchain_record_count": blockchain.get_block_count(),
        "system_status":         _get_system_status(),
        "pps_history":           list(monitor.pps_history),
        "attack_rate_history":   list(monitor.attack_rate_history),
        "node_status":           blockchain.get_node_status(),
    }


@app.get("/api/attacks")
async def get_attacks(limit: int = 20):
    return queries.get_recent_attacks(limit)


@app.get("/api/blockchain")
async def get_blockchain():
    return blockchain.get_chain()


@app.get("/api/blockchain/verify")
async def verify_blockchain():
    return blockchain.verify()


@app.get("/api/blocked")
async def get_blocked():
    return blocker.get_blocked_list()


@app.delete("/api/blocked/{ip}")
async def unblock_ip(ip: str):
    blocker.unblock_ip(ip)
    return {"message": f"{ip} unblocked successfully"}


@app.post("/api/simulate")
async def simulate(req: SimulateRequest):
    """Trigger built-in traffic simulation without the external generator script."""
    import threading

    def _run_simulation():
        import requests as req_lib
        import random
        import time

        normal_ips = [f"192.168.1.{i}" for i in range(1, 31)]
        attack_ips = [f"10.0.0.{i}" for i in range(1, 21)]

        end_time = time.time() + req.duration

        def send_normal():
            while time.time() < end_time:
                ip = random.choice(normal_ips)
                try:
                    req_lib.post(f"http://localhost:{config.PORT}/api/traffic", json={
                        "src_ip": ip, "protocol": "HTTP",
                        "packet_size": random.randint(200, 800),
                        "payload_size": random.randint(100, 500),
                        "syn_flag": False,
                        "src_port": random.randint(1024, 65535),
                        "dst_port": 8000,
                        "dst_ip": "127.0.0.1",
                    }, timeout=2)
                except Exception:
                    pass
                time.sleep(random.uniform(0.05, 0.2))

        def send_attack():
            attack_ip = random.choice(attack_ips)
            while time.time() < end_time:
                try:
                    req_lib.post(f"http://localhost:{config.PORT}/api/traffic", json={
                        "src_ip": attack_ip, "protocol": req.attack_type.upper().replace("_", " "),
                        "packet_size": random.randint(60, 150),
                        "payload_size": random.randint(50, 100),
                        "syn_flag": req.attack_type == "syn_flood",
                        "src_port": random.randint(1024, 65535),
                        "dst_port": 8000,
                        "dst_ip": "127.0.0.1",
                    }, timeout=2)
                except Exception:
                    pass

        threads = []
        if req.mode in ("normal", "mixed"):
            for _ in range(5):
                t = threading.Thread(target=send_normal, daemon=True)
                t.start()
                threads.append(t)

        if req.mode in ("attack", "mixed"):
            for _ in range(40):
                t = threading.Thread(target=send_attack, daemon=True)
                t.start()
                threads.append(t)

    thread = threading.Thread(target=_run_simulation, daemon=True)
    thread.start()
    return {"message": f"Simulation started: mode={req.mode}, duration={req.duration}s"}


# ─── WebSocket ────────────────────────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep connection alive; stats are pushed by broadcaster
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)


# ─── Serve dashboard ──────────────────────────────────────────────────────────

_dash_dir = os.path.join(os.path.dirname(__file__), "..", "dashboard")
if os.path.isdir(_dash_dir):
    app.mount("/dashboard", StaticFiles(directory=_dash_dir, html=True), name="dashboard")
