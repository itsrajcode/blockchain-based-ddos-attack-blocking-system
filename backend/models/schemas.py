"""
models/schemas.py — Pydantic request/response models
"""

from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime


class TrafficPacket(BaseModel):
    """Incoming traffic record from the generator."""
    src_ip: str
    dst_ip: str = "127.0.0.1"
    src_port: int = Field(default=0, ge=0, le=65535)
    dst_port: int = Field(default=8000, ge=0, le=65535)
    protocol: str = "HTTP"
    packet_size: int = Field(default=512, ge=0)
    syn_flag: bool = False
    payload_size: int = 256


class FeatureVector(BaseModel):
    """Extracted feature vector sent to the detection engine."""
    src_ip: str
    protocol: str
    packet_count: int
    total_bytes: int
    avg_packet_size: float
    packets_per_sec: float
    bytes_per_sec: float
    connection_count: int
    syn_count: int
    syn_ratio: float
    dst_port: int
    flow_duration: float


class DetectionResult(BaseModel):
    src_ip: str
    is_attack: bool
    severity: str               # NORMAL | LOW | MEDIUM | HIGH
    attack_type: str
    confidence: float
    detection_method: str       # rules | ml | combined
    packets_per_sec: float
    action: str                 # ALLOW | MONITOR | RATE_LIMIT | BLOCK


class AttackEvent(BaseModel):
    attack_id: str
    timestamp: str
    src_ip: str
    attack_type: str
    severity: str
    packets_per_sec: float
    confidence: float
    detection_method: str
    blockchain_hash: Optional[str] = None
    block_index: int = -1
    status: str = "DETECTED"


class BlockchainBlock(BaseModel):
    index: int
    timestamp: str
    attack_record: dict
    previous_hash: str
    nonce: int
    hash: str
    node: str


class DashboardStats(BaseModel):
    total_requests: int
    normal_count: int
    suspicious_count: int
    attack_count: int
    blocked_ip_count: int
    blockchain_record_count: int
    system_status: str          # PROTECTED | ALERT | UNDER_ATTACK
    active_attacks: List[dict]
    top_attackers: List[dict]
    packets_per_sec_history: List[float]
    attack_rate_history: List[float]
    chain_valid: bool


class SimulateRequest(BaseModel):
    mode: str = "attack"        # normal | attack | mixed
    duration: int = 30          # seconds
    attack_type: str = "http_flood"  # http_flood | udp_flood | syn_flood
