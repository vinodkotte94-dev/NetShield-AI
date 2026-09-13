import subprocess
import threading
import time
from pathlib import Path

from app.services.pcap_ai_prediction import predict_pcap_threats


# ============================================================
# TSHARK CONFIGURATION
# ============================================================

TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"

# Wi-Fi interface
INTERFACE = "5"


# ============================================================
# LIVE MONITOR CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parents[1]

LIVE_DIR = BASE_DIR / "uploads" / "live"

LIVE_DIR.mkdir(
    parents=True,
    exist_ok=True
)

BATCH_SECONDS = 10


# ============================================================
# LIVE MONITOR STATE
# ============================================================

monitor_process = None
monitor_thread = None

monitor_running = False

packet_count = 0
flow_count = 0
threat_count = 0
benign_count = 0

last_prediction = None

start_time = None

lock = threading.Lock()


# ============================================================
# LIVE BATCH PROCESSOR
# ============================================================

def _capture_batch():

    global monitor_process
    global packet_count
    global flow_count
    global threat_count
    global benign_count
    global last_prediction
    global monitor_running

    batch_number = 0

    while monitor_running:

        batch_number += 1

        pcap_path = (
            LIVE_DIR
            / f"live_batch_{batch_number}.pcapng"
        )

        command = [
            TSHARK_PATH,
            "-i",
            INTERFACE,
            "-a",
            f"duration:{BATCH_SECONDS}",
            "-w",
            str(pcap_path)
        ]

        print("------------------------------------------")
        print(
            f"Starting live capture batch "
            f"{batch_number}"
        )
        print(
            f"Duration: {BATCH_SECONDS} seconds"
        )

        try:

            monitor_process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )

            # Read TShark output so the process does not
            # get blocked by its output pipe.
            output_lines = []

            while (
                monitor_process.poll() is None
                and monitor_running
            ):

                line = (
                    monitor_process.stdout.readline()
                )

                if line:

                    output_lines.append(
                        line.strip()
                    )

                else:

                    time.sleep(0.05)

            # Stop capture if user requested stop.
            if (
                not monitor_running
                and monitor_process
            ):

                try:
                    monitor_process.terminate()
                except Exception:
                    pass

            # Wait for TShark to finish.
            if monitor_process:

                try:
                    monitor_process.wait(
                        timeout=5
                    )
                except Exception:
                    pass

            monitor_process = None

            # ------------------------------------------------
            # Process captured batch
            # ------------------------------------------------

            if not pcap_path.exists():

                print(
                    "No PCAP file created."
                )

                continue

            if pcap_path.stat().st_size <= 0:

                print(
                    "Empty PCAP batch."
                )

                try:
                    pcap_path.unlink()
                except Exception:
                    pass

                continue

            print(
                f"PCAP batch created: "
                f"{pcap_path.name}"
            )

            try:

                result = predict_pcap_threats(
                    str(pcap_path)
                )

                with lock:

                    last_prediction = result

                    flow_count = int(
                        result.get(
                            "total_flows",
                            0
                        )
                    )

                    threat_count = int(
                        result.get(
                            "total_threats",
                            0
                        )
                    )

                    benign_count = int(
                        result.get(
                            "total_benign",
                            0
                        )
                    )

                print("------------------------------------------")
                print(
                    "LIVE AI ANALYSIS RESULT"
                )
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

            except Exception as prediction_error:

                print(
                    "Live AI prediction error:",
                    str(prediction_error)
                )

            # ------------------------------------------------
            # Count packets from TShark summary
            # ------------------------------------------------

            captured_packets = 0

            for line in output_lines:

                if "packets captured" in line.lower():

                    parts = line.split()

                    for index, value in enumerate(parts):

                        if (
                            value.isdigit()
                            and index + 1 < len(parts)
                            and "packet" in parts[index + 1].lower()
                        ):

                            captured_packets = int(
                                value
                            )

                            break

            if captured_packets > 0:

                with lock:

                    packet_count += (
                        captured_packets
                    )

            # ------------------------------------------------
            # Remove processed PCAP
            # ------------------------------------------------

            try:

                pcap_path.unlink()

            except Exception as cleanup_error:

                print(
                    "PCAP cleanup error:",
                    str(cleanup_error)
                )

        except Exception as capture_error:

            print(
                "Live capture error:",
                str(capture_error)
            )

            monitor_process = None

            if monitor_running:

                time.sleep(2)


    monitor_process = None

    print(
        "Live capture worker stopped."
    )


# ============================================================
# START MONITOR
# ============================================================

def start_monitor():

    global monitor_thread
    global monitor_running

    global packet_count
    global flow_count
    global threat_count
    global benign_count

    global last_prediction
    global start_time

    if monitor_running:

        return {
            "success": True,
            "message":
                "Live monitoring is already running."
        }

    # Reset statistics.
    with lock:

        packet_count = 0
        flow_count = 0
        threat_count = 0
        benign_count = 0
        last_prediction = None

    start_time = time.time()

    monitor_running = True

    monitor_thread = threading.Thread(
        target=_capture_batch,
        daemon=True
    )

    monitor_thread.start()

    return {
        "success": True,
        "message":
            "Live network monitoring started."
    }


# ============================================================
# STOP MONITOR
# ============================================================

def stop_monitor():

    global monitor_running
    global monitor_process

    if not monitor_running:

        return {
            "success": True,
            "message":
                "Live monitoring is not running."
        }

    monitor_running = False

    if monitor_process:

        try:
            monitor_process.terminate()
        except Exception:
            pass

    return {
        "success": True,
        "message":
            "Live network monitoring stopped."
    }


# ============================================================
# LIVE STATUS
# ============================================================

def get_status():

    with lock:

        current_packet_count = packet_count
        current_flow_count = flow_count
        current_threat_count = threat_count
        current_benign_count = benign_count
        current_prediction = last_prediction

    running_time = 0

    if start_time and monitor_running:

        running_time = round(
            time.time() - start_time,
            2
        )

    return {
        "success": True,
        "running": monitor_running,
        "interface": INTERFACE,
        "packet_count": current_packet_count,
        "flow_count": current_flow_count,
        "threat_count": current_threat_count,
        "benign_count": current_benign_count,
        "running_seconds": running_time,
        "last_prediction": current_prediction
    }