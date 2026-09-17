"""
modules/feature_extractor.py — Converts raw monitor snapshot → FeatureVector
"""

from models.schemas import FeatureVector


def extract_features(src_ip: str, snapshot: dict) -> FeatureVector:
    """
    Convert a TrafficMonitor snapshot into a normalised FeatureVector
    ready for the detection engine.
    """
    return FeatureVector(
        src_ip=src_ip,
        protocol=snapshot.get("protocol", "HTTP"),
        packet_count=snapshot.get("packet_count", 0),
        total_bytes=snapshot.get("total_bytes", 0),
        avg_packet_size=snapshot.get("avg_packet_size", 0.0),
        packets_per_sec=snapshot.get("packets_per_sec", 0.0),
        bytes_per_sec=snapshot.get("bytes_per_sec", 0.0),
        connection_count=snapshot.get("connection_count", 0),
        syn_count=snapshot.get("syn_count", 0),
        syn_ratio=snapshot.get("syn_ratio", 0.0),
        dst_port=snapshot.get("dst_port", 8000),
        flow_duration=snapshot.get("flow_duration", 0.0),
    )


def feature_vector_to_list(fv: FeatureVector) -> list:
    """
    Return ordered numeric feature list for ML model input.
    Order must match training column order in ml/train.py.
    """
    return [
        fv.packet_count,
        fv.total_bytes,
        fv.avg_packet_size,
        fv.packets_per_sec,
        fv.bytes_per_sec,
        fv.connection_count,
        fv.syn_count,
        fv.syn_ratio,
        fv.dst_port,
        fv.flow_duration,
    ]
