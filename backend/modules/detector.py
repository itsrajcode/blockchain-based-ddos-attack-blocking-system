"""
modules/detector.py — DDoS Detection Engine (Rule-based + Random Forest ML)
"""

import os
import sys
import pickle
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import config
from models.schemas import FeatureVector, DetectionResult
from modules.feature_extractor import feature_vector_to_list


# ─── Load ML model (best-effort) ──────────────────────────────────────────────

_ml_model = None

def _load_model():
    global _ml_model
    if os.path.exists(config.MODEL_PATH):
        with open(config.MODEL_PATH, "rb") as f:
            _ml_model = pickle.load(f)
        print(f"[Detector] ML model loaded from {config.MODEL_PATH}")
    else:
        print("[Detector] ML model not found — using rule-based detection only.")

_load_model()


# ─── Attack type inference ─────────────────────────────────────────────────────

def _infer_attack_type(fv: FeatureVector) -> str:
    if fv.syn_ratio > 0.7:
        return "SYN Flood"
    if fv.connection_count > 200 and fv.packets_per_sec > 500:
        return "HTTP Flood"
    if fv.protocol == "UDP" or fv.dst_port > 10000:
        return "UDP Flood"
    if fv.connection_count > 150 and fv.packets_per_sec < 100:
        return "Slowloris"
    return "HTTP Flood"


# ─── Rule-based severity ──────────────────────────────────────────────────────

def _rule_based_severity(fv: FeatureVector) -> str:
    th = config.THRESHOLDS
    pps = fv.packets_per_sec
    conn = fv.connection_count
    bps = fv.bytes_per_sec
    syn = fv.syn_ratio

    if (pps >= th["packets_per_sec_high"]
            or conn >= th["connection_count_high"]
            or bps >= th["bytes_per_sec_high"]
            or syn >= th["syn_ratio_high"]):
        return "HIGH"

    if (pps >= th["packets_per_sec_medium"]
            or conn >= th["connection_count_medium"]):
        return "MEDIUM"

    if (pps >= th["packets_per_sec_low"]
            or conn >= th["connection_count_low"]):
        return "LOW"

    return "NORMAL"


# ─── Main detection function ───────────────────────────────────────────────────

def detect(fv: FeatureVector) -> DetectionResult:
    """
    Run detection on a feature vector.
    Returns a DetectionResult with severity, attack type, and action.
    """
    # ── Rule-based ─────────────────────────────────────────────────────────────
    rule_severity = _rule_based_severity(fv)
    rule_is_attack = rule_severity != "NORMAL"

    # ── ML-based (if model available) ─────────────────────────────────────────
    ml_is_attack = False
    ml_confidence = 0.0
    method = "rules"

    if _ml_model is not None:
        features = [feature_vector_to_list(fv)]
        ml_pred = _ml_model.predict(features)[0]
        proba = _ml_model.predict_proba(features)[0]
        ml_confidence = float(max(proba))
        ml_is_attack = bool(ml_pred == 1)
        method = "ml"

        # ── Combined decision ─────────────────────────────────────────────────
        # Trust ML only when confidence is high enough
        if ml_confidence >= config.ML_CONFIDENCE_THRESHOLD:
            is_attack = ml_is_attack or rule_is_attack
            method = "combined"
        else:
            # Fall back to rules when ML is uncertain
            is_attack = rule_is_attack
            method = "rules+ml_uncertain"
    else:
        is_attack = rule_is_attack
        ml_confidence = 1.0 if rule_is_attack else 0.0

    # ── Severity & attack type ─────────────────────────────────────────────────
    severity = rule_severity if not is_attack else (
        rule_severity if rule_severity != "NORMAL" else "HIGH"
    )

    attack_type = _infer_attack_type(fv) if is_attack else "None"

    # ── Action mapping ─────────────────────────────────────────────────────────
    action_map = {
        "NORMAL": "ALLOW",
        "LOW":    "MONITOR",
        "MEDIUM": "RATE_LIMIT",
        "HIGH":   "BLOCK",
    }
    action = action_map[severity]

    confidence = ml_confidence if _ml_model else (1.0 if is_attack else 0.05)

    return DetectionResult(
        src_ip=fv.src_ip,
        is_attack=is_attack,
        severity=severity,
        attack_type=attack_type,
        confidence=round(confidence, 4),
        detection_method=method,
        packets_per_sec=fv.packets_per_sec,
        action=action,
    )
