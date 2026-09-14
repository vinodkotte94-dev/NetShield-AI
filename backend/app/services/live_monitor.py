import threading
import time


# ============================================================
# LIVE MONITOR STATE
# ============================================================

monitor_running = False

packet_count = 0
flow_count = 0
threat_count = 0
benign_count = 0

last_prediction = None

start_time = None

lock = threading.Lock()


# ============================================================
# START LIVE MONITOR
# ============================================================

def start_monitor():

    global monitor_running
    global packet_count
    global flow_count
    global threat_count
    global benign_count
    global last_prediction
    global start_time

    with lock:

        if monitor_running:

            return {
                "success": True,
                "message":
                    "Live monitoring is already running."
            }

        # Reset live statistics.
        packet_count = 0
        flow_count = 0
        threat_count = 0
        benign_count = 0

        last_prediction = None

        start_time = time.time()

        monitor_running = True

    print("------------------------------------------")
    print("Live monitoring started.")
    print("Waiting for NetShield Agent results...")
    print("------------------------------------------")

    return {
        "success": True,
        "message":
            "Live network monitoring started."
    }


# ============================================================
# STOP LIVE MONITOR
# ============================================================

def stop_monitor():

    global monitor_running

    with lock:

        if not monitor_running:

            return {
                "success": True,
                "message":
                    "Live monitoring is not running."
            }

        monitor_running = False

    print("------------------------------------------")
    print("Live monitoring stopped.")
    print("------------------------------------------")

    return {
        "success": True,
        "message":
            "Live network monitoring stopped."
    }


# ============================================================
# UPDATE LIVE RESULT FROM AGENT
# ============================================================

def update_from_agent(result):

    global packet_count
    global flow_count
    global threat_count
    global benign_count
    global last_prediction

    if not result:

        return {
            "success": False,
            "message":
                "Empty Agent result."
        }

    with lock:

        # Update the latest AI prediction.
        last_prediction = result

        # Update flow statistics.
        flow_count = int(
            result.get(
                "total_flows",
                0
            )
        )

        # Update threat statistics.
        threat_count = int(
            result.get(
                "total_threats",
                0
            )
        )

        # Update benign statistics.
        benign_count = int(
            result.get(
                "total_benign",
                0
            )
        )

        # Agent currently captures 10-second batches.
        # Packet count can be supplied by the Agent
        # when available.
        captured_packets = int(
            result.get(
                "packet_count",
                0
            )
        )

        if captured_packets > 0:

            packet_count += captured_packets

    print("------------------------------------------")
    print("LIVE AGENT RESULT RECEIVED")
    print("------------------------------------------")
    print(
        f"Flows   : {flow_count}"
    )
    print(
        f"Threats : {threat_count}"
    )
    print(
        f"Benign  : {benign_count}"
    )
    print(
        f"Severity: "
        f"{result.get('severity')}"
    )
    print("------------------------------------------")

    return {
        "success": True,
        "message":
            "Live monitoring result updated."
    }


# ============================================================
# GET LIVE STATUS
# ============================================================

def get_status():

    with lock:

        current_running = monitor_running

        current_packet_count = packet_count

        current_flow_count = flow_count

        current_threat_count = threat_count

        current_benign_count = benign_count

        current_prediction = last_prediction

        current_start_time = start_time

    running_time = 0

    if (
        current_start_time
        and current_running
    ):

        running_time = round(
            time.time()
            - current_start_time,
            2
        )

    return {
        "success": True,

        "running": current_running,

        "interface":
            "NetShield Agent",

        "packet_count":
            current_packet_count,

        "flow_count":
            current_flow_count,

        "threat_count":
            current_threat_count,

        "benign_count":
            current_benign_count,

        "running_seconds":
            running_time,

        "last_prediction":
            current_prediction
    }