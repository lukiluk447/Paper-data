import sys
from scapy.all import rdpcap, Raw, TCP, IP
import pandas as pd
import os

TARGET_IP = "192.168.1.101"
EXCEL_FILE = "analysis.csv"

HTTP_METHODS = [b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH"]

def is_tls_packet(payload_bytes):
    """
    Check if the payload looks like a TLS record.
    TLS record format:
    Byte 0: Content type (0x14, 0x15, 0x16, 0x17)
    Bytes 1-2: Version (0x0300-0x0304)
    Bytes 3-4: Length
    """
    if len(payload_bytes) < 5:
        return False
    content_type = payload_bytes[0]
    version_major, version_minor = payload_bytes[1], payload_bytes[2]

    # TLS content types: 20-23 decimal (0x14-0x17)
    if content_type not in [20, 21, 22, 23]:
        return False
    # TLS versions 3.0-3.4 (TLS 1.0 to TLS 1.3)
    if version_major != 3 or version_minor not in [0, 1, 2, 3, 4]:
        return False
    return True

def is_http_packet(payload_bytes):
    """
    Check if the payload looks like an HTTP request.
    """
    for method in HTTP_METHODS:
        if payload_bytes.startswith(method):
            return True
    return False

def count_packets(pcap_file):
    packets = rdpcap(pcap_file)
    http_count = 0
    tls_count = 0

    for pkt in packets:
        if IP in pkt and TCP in pkt:
            if pkt[IP].src != TARGET_IP:
                continue

            payload = bytes(pkt[Raw].load) if Raw in pkt else b""

            if len(payload) == 0:
                continue

            if is_tls_packet(payload):
                tls_count += 1
            elif is_http_packet(payload):
                http_count += 1
            # else: ignore non-HTTP, non-TLS traffic

    return http_count, tls_count

def append_to_excel(mitm_status, http_count, tls_count):
    data = {
        "MITM": [mitm_status],
        "HTTP_packets": [http_count],
        "TLS_packets": [tls_count]
    }

    df = pd.DataFrame(data)

    if not os.path.isfile(EXCEL_FILE):
        df.to_csv(EXCEL_FILE, index=False)
    else:
        df.to_csv(EXCEL_FILE, mode="a", header=False, index=False)

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 scan_packets.py <pcap-file> <mitm-status>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    mitm_status = int(sys.argv[2])

    http_count, tls_count = count_packets(pcap_file)

    if http_count == 0 & tls_count == 0:
        mitm_status = 0
    append_to_excel(mitm_status, http_count, tls_count)
    print(f"Row added: MITM={mitm_status}, HTTP={http_count}, TLS={tls_count}")

if __name__ == "__main__":
    main()
