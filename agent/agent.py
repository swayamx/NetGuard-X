from scapy.all import sniff
import requests

SERVER_URL = "http://127.0.0.1:5000/ingest"
# Replace with deployed URL later

def process_packet(packet):
    try:
        size = len(packet)
        proto = packet.proto if hasattr(packet, 'proto') else 0

        data = {
            "size": size,
            "proto": proto
        }

        requests.post(SERVER_URL, json=data)

        print(f"Sent packet: Size={size}, Proto={proto}")

    except:
        pass

# Start capturing
sniff(prn=process_packet)
