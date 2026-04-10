from latency import dection_latency
from ARP_reply_detection import dection_arp 
from logs import loging
import sys
from time import sleep
import threading
import queue
import time 

def main_latency(target_ip,ping_hoeveelheid, laytency_bar):
    begin = time.time_ns()

    gemiddelde,results = dection_latency(target_ip, ping_hoeveelheid)

    if gemiddelde > laytency_bar:
        end = time.time_ns()
        loging.write_to_file(f"Waarschuwing: Vermoedelijke MITM-aanval gedetecteerd! Gemiddelde latency is {gemiddelde} ms")
    else:
        end = time.time_ns()

    loging.write_to_file(f"Time it took was: {end-begin} nano sec")
    loging.write_to_file(f"laytency was {gemiddelde}")

    return gemiddelde,results

ip  = "192.168.1.1"
pings = 5
laytency_bar = 10
#ip = input("What is the ip: ")

#print(main_latency(ip,pings,laytency_bar))

#pings = int(input("how many pings do we need to do: "))
for i in range(20):
     loging.write_to_file(f"Begin test {i+1}")
     print(main_latency(ip,pings,laytency_bar))
     loging.write_to_file(f"End test")
     sleep(20)