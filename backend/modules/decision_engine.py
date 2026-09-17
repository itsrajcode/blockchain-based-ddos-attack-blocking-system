"""
modules/decision_engine.py — Translates detection severity into a structured action
"""

from models.schemas import DetectionResult


SEVERITY_COLORS = {
    "NORMAL": "#00ff88",
    "LOW":    "#ffd700",
    "MEDIUM": "#ff8c00",
    "HIGH":   "#ff2d55",
}

ACTION_DESCRIPTIONS = {
    "ALLOW":      "Traffic is within normal parameters. Allowed through.",
    "MONITOR":    "Elevated activity detected. Monitoring without blocking.",
    "RATE_LIMIT": "Suspicious traffic rate. Connection rate limited.",
    "BLOCK":      "DDoS attack confirmed. IP blocked immediately.",
}


def decide(result: DetectionResult) -> dict:
    """
    Returns an enriched decision dict with colour, description, and priority.
    """
    color = SEVERITY_COLORS.get(result.severity, "#ffffff")
    description = ACTION_DESCRIPTIONS.get(result.action, "")

    priority = {
        "ALLOW":      0,
        "MONITOR":    1,
        "RATE_LIMIT": 2,
        "BLOCK":      3,
    }.get(result.action, 0)

    return {
        "src_ip":           result.src_ip,
        "action":           result.action,
        "severity":         result.severity,
        "severity_color":   color,
        "attack_type":      result.attack_type,
        "description":      description,
        "priority":         priority,
        "should_block":     result.action == "BLOCK",
        "should_log":       result.action != "ALLOW",
        "packets_per_sec":  result.packets_per_sec,
        "confidence":       result.confidence,
        "detection_method": result.detection_method,
    }
