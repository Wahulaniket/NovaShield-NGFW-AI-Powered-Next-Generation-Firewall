from pathlib import Path
import time

import joblib
import numpy as np
from scapy.all import IP, IPv6, TCP, UDP, sniff

try:
    from model import predict
except ImportError:
    from ai_engine.model import predict


def load_features_list():
    """Load expected feature order from disk if available."""
    features_path = Path(__file__).resolve().parent / "model" / "models" / "features.pkl"
    if features_path.exists():
        return joblib.load(features_path)

    print(f"[WARN] Missing features file: {features_path}. Using fallback defaults.")
    return []


FEATURES_LIST = load_features_list()

# Store bidirectional flows
flows = {}

FLOW_TIMEOUT = 3  # seconds
PACKET_TRIGGER = 8

# Safety guard for obvious high-rate behavior
RATE_PACKET_THRESHOLD = 8
RATE_DURATION_THRESHOLD = 1.0
FLOW_BYTES_PER_SEC_BLOCK = 20000.0


def _stats(values):
    if not values:
        return 0.0, 0.0, 0.0
    return float(np.mean(values)), float(np.std(values)), float(np.max(values))


def _extract_ip_port_proto(packet):
    if IP in packet:
        ip = packet[IP]
        src = ip.src
        dst = ip.dst
        proto = ip.proto
    elif IPv6 in packet:
        ip = packet[IPv6]
        src = ip.src
        dst = ip.dst
        proto = getattr(ip, "nh", 0)
    else:
        return None

    if TCP in packet:
        sport = int(packet[TCP].sport)
        dport = int(packet[TCP].dport)
    elif UDP in packet:
        sport = int(packet[UDP].sport)
        dport = int(packet[UDP].dport)
    else:
        sport = 0
        dport = 0

    return src, dst, sport, dport, int(proto)


def get_flow_key(packet):
    """
    Return canonical bidirectional flow key + packet direction.
    direction is from endpoint_a -> endpoint_b based on lexical ordering.
    """
    parsed = _extract_ip_port_proto(packet)
    if parsed is None:
        return None, None

    src, dst, sport, dport, proto = parsed
    endpoint_src = (src, sport)
    endpoint_dst = (dst, dport)

    if endpoint_src <= endpoint_dst:
        key = (endpoint_src, endpoint_dst, proto)
        direction = "fwd"
    else:
        key = (endpoint_dst, endpoint_src, proto)
        direction = "bwd"

    return key, direction


def _l4_header_len(packet):
    if TCP in packet:
        return int(getattr(packet[TCP], "dataofs", 0) or 0) * 4
    if UDP in packet:
        return 8
    return 0


def _build_features(key, flow):
    all_lengths = flow["all_lengths"]
    fwd_lengths = flow["fwd_lengths"]
    bwd_lengths = flow["bwd_lengths"]

    mean_all, std_all, max_all = _stats(all_lengths)
    mean_fwd, std_fwd, max_fwd = _stats(fwd_lengths)
    mean_bwd, std_bwd, max_bwd = _stats(bwd_lengths)

    duration = max(time.time() - flow["start_time"], 1e-6)

    features = {
        "Max Packet Length": max_all,
        "Packet Length Mean": mean_all,
        "Packet Length Std": std_all,
        "Packet Length Variance": float(np.var(all_lengths)) if all_lengths else 0.0,
        "Average Packet Size": mean_all,
        "Destination Port": flow["destination_port"],
        "Total Length of Fwd Packets": float(flow["fwd_bytes"]),
        "Total Length of Bwd Packets": float(flow["bwd_bytes"]),
        "Subflow Fwd Bytes": float(flow["fwd_bytes"]),
        "Subflow Bwd Bytes": float(flow["bwd_bytes"]),
        "Fwd Packet Length Max": max_fwd,
        "Fwd Packet Length Mean": mean_fwd,
        "Fwd Packet Length Std": std_fwd,
        "Bwd Packet Length Max": max_bwd,
        "Bwd Packet Length Mean": mean_bwd,
        "Bwd Packet Length Std": std_bwd,
        "Avg Fwd Segment Size": mean_fwd,
        "Avg Bwd Segment Size": mean_bwd,
        "Total Fwd Packets": float(len(fwd_lengths)),
        "Flow Bytes/s": float(flow["bytes"]) / duration,
        "Fwd Header Length": float(flow["fwd_header_len"]),
        "Fwd Header Length.1": float(flow["fwd_header_len"]),
        "Bwd Header Length": float(flow["bwd_header_len"]),
        "Init_Win_bytes_forward": float(flow["init_win_fwd"]),
        "Init_Win_bytes_backward": float(flow["init_win_bwd"]),
    }

    for feature_name in FEATURES_LIST:
        if feature_name not in features:
            features[feature_name] = 0.0

    return features


def get_decision_from_result(result, features, flow):
    """
    Final decision = model label + safety guard for clear burst traffic.
    """
    label = str(result.get("label", result.get("predicted_class", "UNKNOWN"))).strip().upper()

    duration = max(time.time() - flow["start_time"], 1e-6)
    total_packets = len(flow["all_lengths"])
    bytes_per_sec = float(features.get("Flow Bytes/s", 0.0))

    if (
        total_packets >= RATE_PACKET_THRESHOLD
        and duration <= RATE_DURATION_THRESHOLD
    ) or bytes_per_sec >= FLOW_BYTES_PER_SEC_BLOCK:
        return "block", "rate_guard_triggered"

    return ("allow", "model_benign") if label == "BENIGN" else ("block", "model_attack")


def extract_features(key, flow):
    if len(flow["all_lengths"]) == 0:
        return None

    features = _build_features(key, flow)
    feature_vector = [features[feature_name] for feature_name in FEATURES_LIST]

    model_input = {
        "features": features,
        "feature_vector": feature_vector,
    }

    try:
        result = predict(model_input)
    except Exception as exc:
        result = {"label": "ERROR", "reason": str(exc)}

    decision, decision_reason = get_decision_from_result(result, features, flow)

    print("\n==============================")
    print(f"Flow: {key}")
    print(f"Packets: {len(flow['all_lengths'])} | Bytes: {flow['bytes']}")
    print("AI Result:", result)
    print(f"Decision: {decision} ({decision_reason})")
    print("==============================\n")

    return {
        "flow_key": key,
        "features": features,
        "result": result,
        "decision": decision,
        "decision_reason": decision_reason,
    }


def process_packet(packet):
    key, direction = get_flow_key(packet)
    if key is None:
        return

    now = time.time()

    if key not in flows:
        # Recover destination port from packet for feature compatibility.
        dport = 0
        if TCP in packet:
            dport = int(packet[TCP].dport)
        elif UDP in packet:
            dport = int(packet[UDP].dport)

        flows[key] = {
            "start_time": now,
            "bytes": 0,
            "all_lengths": [],
            "fwd_lengths": [],
            "bwd_lengths": [],
            "fwd_header_len": 0,
            "bwd_header_len": 0,
            "init_win_fwd": 0,
            "init_win_bwd": 0,
            "fwd_bytes": 0,
            "bwd_bytes": 0,
            "destination_port": dport,
        }

    flow = flows[key]
    pkt_len = int(len(packet))
    hdr_len = _l4_header_len(packet)

    flow["bytes"] += pkt_len
    flow["all_lengths"].append(pkt_len)

    if direction == "fwd":
        flow["fwd_lengths"].append(pkt_len)
        flow["fwd_header_len"] += hdr_len
        flow["fwd_bytes"] += pkt_len
        if flow["init_win_fwd"] == 0 and TCP in packet:
            flow["init_win_fwd"] = int(getattr(packet[TCP], "window", 0) or 0)
    else:
        flow["bwd_lengths"].append(pkt_len)
        flow["bwd_header_len"] += hdr_len
        flow["bwd_bytes"] += pkt_len
        if flow["init_win_bwd"] == 0 and TCP in packet:
            flow["init_win_bwd"] = int(getattr(packet[TCP], "window", 0) or 0)

    # Condition 1: TCP FIN (connection closed)
    if TCP in packet and packet[TCP].flags & 0x01:
        extract_features(key, flow)
        del flows[key]
        return

    # Condition 2: timeout
    if now - flow["start_time"] > FLOW_TIMEOUT:
        extract_features(key, flow)
        del flows[key]
        return

    # Condition 3: packet threshold
    if len(flow["all_lengths"]) >= PACKET_TRIGGER:
        extract_features(key, flow)
        del flows[key]
        return


def start(iface=None):
    print("AI Feature Extractor started...")

    while True:
        try:
            sniff(iface=iface, prn=process_packet, store=False)
        except Exception as exc:
            print("Restarting sniff...", exc)


if __name__ == "__main__":
    start()
