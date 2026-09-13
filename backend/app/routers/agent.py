import subprocess
from pathlib import Path

import requests

TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"
INTERFACE = "5"

BACKEND_URL = "https://netshield-ai-nq52.onrender.com"
USER_ID = "test-user"

BASE_DIR = Path(__file__).resolve().parent
PCAP_FILE = BASE_DIR / "live_capture.pcapng"

print("======================================")
print("       NetShield AI Agent")
print("======================================")
print("Starting network capture...")
print("Interface: Wi-Fi (5)")
print(f"Output: {PCAP_FILE}")
print("")

command = [
    TSHARK_PATH,
    "-i",
    INTERFACE,
    "-a",
    "duration:10",
    "-w",
    str(PCAP_FILE)
]

subprocess.run(command)

print("")
print("Network capture completed.")

if not PCAP_FILE.exists():
    print("PCAP was not created.")
    raise SystemExit(1)

file_size = PCAP_FILE.stat().st_size
print("PCAP created successfully.")
print(f"File size: {file_size} bytes")

print("")
print("Sending PCAP to NetShield AI backend...")
print(f"Backend: {BACKEND_URL}")
print("")

try:
    with open(PCAP_FILE, "rb") as pcap_file:
        response = requests.post(
            f"{BACKEND_URL}/api/agent/analyze",
            headers={"X-User-ID": USER_ID},
            files={
                "file": (
                    PCAP_FILE.name,
                    pcap_file,
                    "application/octet-stream"
                )
            },
            timeout=120
        )

    print(f"Backend HTTP Status: {response.status_code}")
    response.raise_for_status()

    result = response.json()

    print("")
    print("======================================")
    print("       NETSHIELD AI RESULT")
    print("======================================")
    print(f"Total Flows       : {result.get('total_flows', 0)}")
    print(f"Total Threats     : {result.get('total_threats', 0)}")
    print(f"Total Benign      : {result.get('total_benign', 0)}")
    print(f"Threat Percentage : {result.get('threat_percentage', 0)}%")
    print(f"AI Confidence     : {result.get('average_confidence', 0)}%")
    print(f"Main Threat       : {result.get('main_threat')}")
    print(f"Severity          : {result.get('severity')}")
    print(f"Alert Created     : {result.get('alert_created')}")
    print(f"User ID           : {result.get('user_id')}")
    print("======================================")

except requests.RequestException as error:
    print("")
    print("Backend connection failed.")
    print(f"Error: {error}")

except Exception as error:
    print("")
    print("Unexpected error.")
    print(f"Error: {error}")

try:
    if PCAP_FILE.exists():
        PCAP_FILE.unlink()
        print("")
        print("Temporary PCAP deleted.")
except Exception as cleanup_error:
    print(f"PCAP cleanup warning: {cleanup_error}")