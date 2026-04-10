from latency import dection_latency
from ARP_reply_detection import dection_arp 
from logs import loging
import sys
from time import sleep
import threading
import queue
import time

def main(target_ip):
    begin = time.time_ns()

    filtered_results = dection_arp(target_ip) #Filters the list for double ARP replys

    if (len(filtered_results)>1):
        end = time.time_ns()
        loging.write_to_file(f"Waarschuwing: MITM-aanval gedetecteerd! Meerdere ARP-replies ontvangen van {target_ip}:")
        loging.write_to_file("MACS:")
        for ip, mac in filtered_results:
            loging.write_to_file(f"{mac}")
        detected = True
    else:
        end = time.time_ns()
    loging.write_to_file(f"Time it took was: {end-begin} nano sec\n\n")

    return filtered_results


ip  = "192.168.1.1"

#main(ip)
loging.write_to_file(f"begin test")

#ip = input("What is the ip: ")
for i in range(20):
    loging.write_to_file(f"Start scan {i}")
    print(main(ip))
    sleep(20)

loging.write_to_file(f"einde test")