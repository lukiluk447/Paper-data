from scapy.all import sniff, ARP, Ether, srp
import threading
import time
import sys
import logs

def sniff_arp_reply_for_ip(target_ip, results, duration=2   ):
    """
    Sniffs ARP replies for `duration` seconds.
    Records only replies from target_ip in results list as (ip, mac)
    """

    def handle_packet(pkt):
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # ARP reply
            if pkt[ARP].psrc == target_ip:
                mac = pkt[ARP].hwsrc
                results.append((target_ip, mac))

    sniff(
        filter="arp",
        prn=handle_packet,
        store=False,
        timeout=duration  # run for exactly `duration` seconds
    )


def send_arp_request(ip):
    """
    Sends an ARP request to the specified IP address.
    """
    arp_request = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request
    srp(packet, timeout=1, verbose=False)

def filter_dubbel_reply(replys):
    filtered = []

    for ip, mac in replys:
        if (ip,mac) not in filtered:
            filtered.append((ip,mac))
    
    return filtered

def dection_arp (target_ip):

    results = []
    # Start the sniffer thread
    sniff_thread = threading.Thread(
        target=sniff_arp_reply_for_ip,
        args=(target_ip, results, 2),
        daemon=True
    )
    sniff_thread.start()

    # Give sniffer a moment to initialize
    time.sleep(0.5)

    # Send ARP request to trigger replies
    #print(f"Sending ARP request to {target_ip}...")

    #logs.write

    send_arp_request(target_ip)

    # Wait for the sniffer thread to finish
    sniff_thread.join()

    filtered_results = filter_dubbel_reply(results) #Filters the list for double ARP replys

    return filtered_results


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: sudo python {sys.argv[0]} <ip-address>")
        sys.exit(1)

    target_ip = sys.argv[1]

    filtered_results = dection_arp(target_ip) #Filters the list for double ARP replys

    # Show results
    if filtered_results:
        print(f"\nARP replies from {target_ip} received ({len(filtered_results)} total):")
        for ip, mac in filtered_results:
            print(f"{ip} -> {mac}")

    else:
        print(f"\nNo ARP replies received from {target_ip} within 10 seconds.")
