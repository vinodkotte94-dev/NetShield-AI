import math
from collections import defaultdict
from pathlib import Path

import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP

# ============================================================
# CICIDS2017 MODEL FEATURES
# ============================================================

CIC_FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of FwdPackets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet LengthVariance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URGFlag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd SegmentSize",
    "Avg Bwd Segment Size",
    "Fwd Header Length.1",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "ActiveMin",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
]


# ============================================================
# SAFE STATISTICS
# ============================================================

def safe_mean(values):
    if not values:
        return 0.0

    return float(
        sum(values) / len(values)
    )


def safe_std(values):
    if len(values) <= 1:
        return 0.0

    mean = safe_mean(values)

    variance = sum(
        (value - mean) ** 2
        for value in values
    ) / len(values)

    return float(
        math.sqrt(variance)
    )


def safe_min(values):
    if not values:
        return 0.0

    return float(
        min(values)
    )


def safe_max(values):
    if not values:
        return 0.0

    return float(
        max(values)
    )


def safe_sum(values):
    if not values:
        return 0.0

    return float(
        sum(values)
    )


def safe_rate(
    numerator,
    duration_seconds
):
    if duration_seconds <= 0:
        return 0.0

    return float(
        numerator / duration_seconds
    )


# ============================================================
# PACKET INFORMATION
# ============================================================

def get_packet_info(packet):
    """
    Extract basic information from an IP packet.
    """

    if IP not in packet:
        return None

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    protocol = 0
    src_port = 0
    dst_port = 0

    if TCP in packet:

        protocol = 6

        src_port = int(
            packet[TCP].sport
        )

        dst_port = int(
            packet[TCP].dport
        )

    elif UDP in packet:

        protocol = 17

        src_port = int(
            packet[UDP].sport
        )

        dst_port = int(
            packet[UDP].dport
        )

    else:

        protocol = int(
            packet[IP].proto
        )

    return {

        "src_ip":
            src_ip,

        "dst_ip":
            dst_ip,

        "src_port":
            src_port,

        "dst_port":
            dst_port,

        "protocol":
            protocol,

        "timestamp":
            float(packet.time),

        "length":
            int(len(packet)),

        "ip_length":
            int(len(packet[IP])),

    }


# ============================================================
# TCP FLAGS
# ============================================================

def get_tcp_flags(packet):
    """
    Return TCP flag information.
    """

    flags = {

        "FIN": 0,
        "SYN": 0,
        "RST": 0,
        "PSH": 0,
        "ACK": 0,
        "URG": 0,
        "CWE": 0,
        "ECE": 0,

    }

    if TCP not in packet:
        return flags

    tcp_flags = int(
        packet[TCP].flags
    )

    flags["FIN"] = (
        1 if tcp_flags & 0x01 else 0
    )

    flags["SYN"] = (
        1 if tcp_flags & 0x02 else 0
    )

    flags["RST"] = (
        1 if tcp_flags & 0x04 else 0
    )

    flags["PSH"] = (
        1 if tcp_flags & 0x08 else 0
    )

    flags["ACK"] = (
        1 if tcp_flags & 0x10 else 0
    )

    flags["URG"] = (
        1 if tcp_flags & 0x20 else 0
    )

    flags["ECE"] = (
        1 if tcp_flags & 0x40 else 0
    )

    flags["CWE"] = (
        1 if tcp_flags & 0x80 else 0
    )

    return flags


# ============================================================
# FLOW KEY
# ============================================================

def make_flow_key(info):
    """
    Create a bidirectional flow key.

    Forward and reverse packets belong to the same flow.
    """

    endpoint_a = (
        info["src_ip"],
        info["src_port"],
    )

    endpoint_b = (
        info["dst_ip"],
        info["dst_port"],
    )

    if endpoint_a <= endpoint_b:

        first = endpoint_a
        second = endpoint_b

    else:

        first = endpoint_b
        second = endpoint_a

    return (

        first[0],
        first[1],

        second[0],
        second[1],

        info["protocol"],

    )


# ============================================================
# FLOW FEATURE CALCULATION
# ============================================================

def calculate_flow_features(flow):
    """
    Convert one packet flow into CICIDS2017-style
    numeric features.
    """

    packets = sorted(
        flow["packets"],
        key=lambda p: p["timestamp"]
    )

    if not packets:
        return None

    first_packet = packets[0]

    forward_ip = (
        flow["forward_src_ip"]
    )

    forward_port = (
        flow["forward_src_port"]
    )

    forward_packets = []
    backward_packets = []

    for packet in packets:

        if (
            packet["src_ip"] == forward_ip
            and packet["src_port"] == forward_port
        ):

            forward_packets.append(
                packet
            )

        else:

            backward_packets.append(
                packet
            )

    all_lengths = [
        packet["length"]
        for packet in packets
    ]

    fwd_lengths = [
        packet["length"]
        for packet in forward_packets
    ]

    bwd_lengths = [
        packet["length"]
        for packet in backward_packets
    ]

    timestamps = [
        packet["timestamp"]
        for packet in packets
    ]

    fwd_timestamps = [
        packet["timestamp"]
        for packet in forward_packets
    ]

    bwd_timestamps = [
        packet["timestamp"]
        for packet in backward_packets
    ]

    first_time = min(
        timestamps
    )

    last_time = max(
        timestamps
    )

    duration_microseconds = (
        last_time - first_time
    ) * 1_000_000

    duration_seconds = (
        last_time - first_time
    )

    # --------------------------------------------------------
    # IAT
    # --------------------------------------------------------

    flow_iats = [

        timestamps[i]
        - timestamps[i - 1]

        for i in range(
            1,
            len(timestamps)
        )

    ]

    fwd_iats = [

        fwd_timestamps[i]
        - fwd_timestamps[i - 1]

        for i in range(
            1,
            len(fwd_timestamps)
        )

    ]

    bwd_iats = [

        bwd_timestamps[i]
        - bwd_timestamps[i - 1]

        for i in range(
            1,
            len(bwd_timestamps)
        )

    ]

    flow_iats_us = [

        value * 1_000_000

        for value in flow_iats

    ]

    fwd_iats_us = [

        value * 1_000_000

        for value in fwd_iats

    ]

    bwd_iats_us = [

        value * 1_000_000

        for value in bwd_iats

    ]

    # --------------------------------------------------------
    # TCP FLAGS
    # --------------------------------------------------------

    fwd_flags = [

        get_tcp_flags(packet["original"])

        for packet in forward_packets

    ]

    bwd_flags = [

        get_tcp_flags(packet["original"])

        for packet in backward_packets

    ]

    all_flags = [

        get_tcp_flags(packet["original"])

        for packet in packets

    ]

    # --------------------------------------------------------
    # HEADER LENGTHS
    # --------------------------------------------------------

    fwd_header_lengths = []

    bwd_header_lengths = []

    for packet in forward_packets:

        original = packet["original"]

        if TCP in original:

            header_length = int(

                original[IP].ihl * 4
                + original[TCP].dataofs * 4

            )

        elif UDP in original:

            header_length = int(

                original[IP].ihl * 4
                + 8

            )

        else:

            header_length = int(

                original[IP].ihl * 4

            )

        fwd_header_lengths.append(
            header_length
        )

    for packet in backward_packets:

        original = packet["original"]

        if TCP in original:

            header_length = int(

                original[IP].ihl * 4
                + original[TCP].dataofs * 4

            )

        elif UDP in original:

            header_length = int(

                original[IP].ihl * 4
                + 8

            )

        else:

            header_length = int(

                original[IP].ihl * 4

            )

        bwd_header_lengths.append(
            header_length
        )

    # --------------------------------------------------------
    # ACTIVE / IDLE
    # --------------------------------------------------------

    active_values = []
    idle_values = []

    if len(timestamps) > 1:

        for i in range(
            1,
            len(timestamps)
        ):

            gap = (

                timestamps[i]
                - timestamps[i - 1]

            ) * 1_000_000

            if gap > 1_000_000:

                idle_values.append(
                    gap
                )

            else:

                active_values.append(
                    gap
                )

    # --------------------------------------------------------
    # PACKET COUNTS
    # --------------------------------------------------------

    total_fwd_packets = len(
        forward_packets
    )

    total_bwd_packets = len(
        backward_packets
    )

    total_packets = len(
        packets
    )

    total_fwd_bytes = sum(
        fwd_lengths
    )

    total_bwd_bytes = sum(
        bwd_lengths
    )

    total_bytes = (

        total_fwd_bytes
        + total_bwd_bytes

    )

    # --------------------------------------------------------
    # DESTINATION PORT
    # --------------------------------------------------------

    destination_port = int(
        first_packet["dst_port"]
    )

    # --------------------------------------------------------
    # MINIMUM TCP SEGMENT SIZE
    # --------------------------------------------------------

    tcp_segment_lengths = []

    for packet in packets:

        original = packet["original"]

        if TCP in original:

            tcp_segment_lengths.append(

                int(
                    len(
                        original[TCP]
                    )
                )

            )

    min_seg_size_forward = (

        min(tcp_segment_lengths)

        if tcp_segment_lengths

        else 0

    )

    # --------------------------------------------------------
    # INITIAL TCP WINDOWS
    # --------------------------------------------------------

    init_win_forward = 0
    init_win_backward = 0

    for packet in forward_packets:

        original = packet["original"]

        if TCP in original:

            init_win_forward = int(
                original[TCP].window
            )

            break

    for packet in backward_packets:

        original = packet["original"]

        if TCP in original:

            init_win_backward = int(
                original[TCP].window
            )

            break

    # --------------------------------------------------------
    # DATA PACKETS
    # --------------------------------------------------------

    active_data_pkt_fwd = sum(

        1

        for packet in forward_packets

        if packet["payload_length"] > 0

    )

    # --------------------------------------------------------
    # FEATURE DICTIONARY
    # --------------------------------------------------------

    features = {

        "Destination Port":
            destination_port,

        "Flow Duration":
            duration_microseconds,

        "Total Fwd Packets":
            total_fwd_packets,

        "Total Backward Packets":
            total_bwd_packets,

        "Total Length of FwdPackets":
            total_fwd_bytes,

        "Total Length of Bwd Packets":
            total_bwd_bytes,

        "Fwd Packet Length Max":
            safe_max(fwd_lengths),

        "Fwd Packet Length Min":
            safe_min(fwd_lengths),

        "Fwd Packet Length Mean":
            safe_mean(fwd_lengths),

        "Fwd Packet Length Std":
            safe_std(fwd_lengths),

        "Bwd Packet Length Max":
            safe_max(bwd_lengths),

        "Bwd Packet Length Min":
            safe_min(bwd_lengths),

        "Bwd Packet Length Mean":
            safe_mean(bwd_lengths),

        "Bwd Packet Length Std":
            safe_std(bwd_lengths),

        "Flow Bytes/s":
            safe_rate(
                total_bytes,
                duration_seconds
            ),

        "Flow Packets/s":
            safe_rate(
                total_packets,
                duration_seconds
            ),

        "Flow IAT Mean":
            safe_mean(flow_iats_us),

        "Flow IAT Std":
            safe_std(flow_iats_us),

        "Flow IAT Max":
            safe_max(flow_iats_us),

        "Flow IAT Min":
            safe_min(flow_iats_us),

        "Fwd IAT Total":
            safe_sum(fwd_iats_us),

        "Fwd IAT Mean":
            safe_mean(fwd_iats_us),

        "Fwd IAT Std":
            safe_std(fwd_iats_us),

        "Fwd IAT Max":
            safe_max(fwd_iats_us),

        "Fwd IAT Min":
            safe_min(fwd_iats_us),

        "Bwd IAT Total":
            safe_sum(bwd_iats_us),

        "Bwd IAT Mean":
            safe_mean(bwd_iats_us),

        "Bwd IAT Std":
            safe_std(bwd_iats_us),

        "Bwd IAT Max":
            safe_max(bwd_iats_us),

        "Bwd IAT Min":
            safe_min(bwd_iats_us),

        "Fwd PSH Flags":
            sum(
                flag["PSH"]
                for flag in fwd_flags
            ),

        "Bwd PSH Flags":
            sum(
                flag["PSH"]
                for flag in bwd_flags
            ),

        "Fwd URG Flags":
            sum(
                flag["URG"]
                for flag in fwd_flags
            ),

        "Bwd URG Flags":
            sum(
                flag["URG"]
                for flag in bwd_flags
            ),

        "Fwd Header Length":
            sum(
                fwd_header_lengths
            ),

        "Bwd Header Length":
            sum(
                bwd_header_lengths
            ),

        "Fwd Packets/s":
            safe_rate(
                total_fwd_packets,
                duration_seconds
            ),

        "Bwd Packets/s":
            safe_rate(
                total_bwd_packets,
                duration_seconds
            ),

        "Min Packet Length":
            safe_min(all_lengths),

        "Max Packet Length":
            safe_max(all_lengths),

        "Packet Length Mean":
            safe_mean(all_lengths),

        "Packet Length Std":
            safe_std(all_lengths),

        "Packet LengthVariance":
            safe_std(all_lengths) ** 2,

        "FIN Flag Count":
            sum(
                flag["FIN"]
                for flag in all_flags
            ),

        "SYN Flag Count":
            sum(
                flag["SYN"]
                for flag in all_flags
            ),

        "RST Flag Count":
            sum(
                flag["RST"]
                for flag in all_flags
            ),

        "PSH Flag Count":
            sum(
                flag["PSH"]
                for flag in all_flags
            ),

        "ACK Flag Count":
            sum(
                flag["ACK"]
                for flag in all_flags
            ),

        "URGFlag Count":
            sum(
                flag["URG"]
                for flag in all_flags
            ),

        "CWE Flag Count":
            sum(
                flag["CWE"]
                for flag in all_flags
            ),

        "ECE Flag Count":
            sum(
                flag["ECE"]
                for flag in all_flags
            ),

        "Down/Up Ratio":

            (
                total_bwd_packets
                / total_fwd_packets
            )

            if total_fwd_packets > 0

            else 0,

        "Average Packet Size":

            (
                total_bytes
                / total_packets
            )

            if total_packets > 0

            else 0,

        "Avg Fwd SegmentSize":
            safe_mean(fwd_lengths),

        "Avg Bwd Segment Size":
            safe_mean(bwd_lengths),

        "Fwd Header Length.1":
            sum(
                fwd_header_lengths
            ),

        "Fwd Avg Bytes/Bulk":
            0,

        "Fwd Avg Packets/Bulk":
            0,

        "Fwd Avg Bulk Rate":
            0,

        "Bwd Avg Bytes/Bulk":
            0,

        "Bwd Avg Packets/Bulk":
            0,

        "Bwd Avg Bulk Rate":
            0,

        "Subflow Fwd Packets":
            total_fwd_packets,

        "Subflow Fwd Bytes":
            total_fwd_bytes,

        "Subflow Bwd Packets":
            total_bwd_packets,

        "Subflow Bwd Bytes":
            total_bwd_bytes,

        "Init_Win_bytes_forward":
            init_win_forward,

        "Init_Win_bytes_backward":
            init_win_backward,

        "act_data_pkt_fwd":
            active_data_pkt_fwd,

        "min_seg_size_forward":
            min_seg_size_forward,

        "Active Mean":
            safe_mean(active_values),

        "Active Std":
            safe_std(active_values),

        "Active Max":
            safe_max(active_values),

        "ActiveMin":
            safe_min(active_values),

        "Idle Mean":
            safe_mean(idle_values),

        "Idle Std":
            safe_std(idle_values),

        "Idle Max":
            safe_max(idle_values),

        "Idle Min":
            safe_min(idle_values),

    }

    return features


# ============================================================
# EXTRACT FLOWS FROM PCAP
# ============================================================

def extract_cic_flows(file_path):
    """
    Read a PCAP/PCAPNG file and convert packets
    into CICIDS2017-style flow feature rows.
    """

    path = Path(
        file_path
    )

    if not path.exists():

        raise FileNotFoundError(
            f"PCAP file not found: {file_path}"
        )

    print(
        "\n=========================================="
    )

    print(
        "PCAP → CIC FLOW FEATURE EXTRACTION"
    )

    print(
        "=========================================="
    )

    print(
        f"Reading PCAP: {path}"
    )

    packets = rdpcap(
        str(path)
    )

    print(
        f"Packets loaded: {len(packets)}"
    )

    flows = defaultdict(

        lambda: {

            "packets": [],

            "forward_src_ip": None,

            "forward_src_port": None,

        }

    )

    for packet in packets:

        info = get_packet_info(
            packet
        )

        if info is None:
            continue

        payload_length = 0

        if TCP in packet:

            payload_length = len(
                bytes(
                    packet[TCP].payload
                )
            )

        elif UDP in packet:

            payload_length = len(
                bytes(
                    packet[UDP].payload
                )
            )

        info["payload_length"] = (
            payload_length
        )

        info["original"] = packet

        flow_key = make_flow_key(
            info
        )

        if (
            flows[flow_key][
                "forward_src_ip"
            ]
            is None
        ):

            flows[flow_key][
                "forward_src_ip"
            ] = info["src_ip"]

            flows[flow_key][
                "forward_src_port"
            ] = info["src_port"]

        flows[flow_key][
            "packets"
        ].append(info)

    print(
        f"Flows detected: {len(flows)}"
    )

    feature_rows = []

    for flow in flows.values():

        features = (
            calculate_flow_features(
                flow
            )
        )

        if features is not None:

            feature_rows.append(
                features
            )

    df = pd.DataFrame(
        feature_rows
    )

    # --------------------------------------------------------
    # Ensure exact CIC feature columns
    # --------------------------------------------------------

    for column in CIC_FEATURES:

        if column not in df.columns:

            df[column] = 0

    df = df[
        CIC_FEATURES
    ]

    # --------------------------------------------------------
    # Clean invalid values
    # --------------------------------------------------------

    df = df.replace(

        [
            float("inf"),
            float("-inf")
        ],

        0

    )

    df = df.fillna(0)

    print(
        f"Feature rows created: {len(df)}"
    )

    print(
        f"Feature columns created: {len(df.columns)}"
    )

    return df