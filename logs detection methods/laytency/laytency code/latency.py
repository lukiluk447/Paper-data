import subprocess
import sys
import re
from time import sleep
from logs import loging
import time 
def ping(ip):
    # Windows uses -n, Linux/macOS use -c
    param = "-n" if sys.platform.lower().startswith("win") else "-c"
    command = ["ping", param, "1", ip]

    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, text=True)
    except subprocess.CalledProcessError:
        return None  # host unreachable or ping failed

    # Extract time=XX ms
    match = re.search(r'time[=<]\s*([\d.]+)\s*ms', output)
    if match:
        return float(match.group(1))
    return None

def Gemiddelde(lijst):
    som = 0

    for item in lijst:
        som += item

    return som/len(lijst)


def test_laytency(pings):
    delays = []
    pings_failed = 0 

    while len(delays) < pings:

        latency = ping(ip)

        if latency is not None:
            delays.append(latency)
        else:
            pings_failed +=1
    return delays

#pings = int(input("Hoeveel keer moet ik pingen per datapunt? "))

def dection_latency(target_ip, ping_hoeveelheid):
    global ip
    ip = target_ip

    #print(f"Pinging {target_ip}...")
    #loging.write_to_file(f"Pinging {target_ip}...")


    results = test_laytency(ping_hoeveelheid)

    #print("Klaar met pingen.")
    #loging.write_to_file("Klaar met pingen.")

    gemiddelde = Gemiddelde(results)

    return gemiddelde,results


if __name__ == "__main__":
     target_ip = sys.argv[1]
     ping_hoeveelheid = int(sys.argv[2])

     gemiddelde = dection_latency(target_ip, ping_hoeveelheid)

     print(f"Gemiddelde latency naar {target_ip} over {ping_hoeveelheid} pings is {gemiddelde} ms")
     loging.write_to_file(f"Gemiddelde latency naar {target_ip} over {ping_hoeveelheid} pings is {gemiddelde} ms")

    