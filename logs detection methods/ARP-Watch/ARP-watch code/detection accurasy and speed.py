import subprocess
import time
from datetime import datetime
import os
from openpyxl import Workbook

# === CONFIG ===
INTERFACE = "eth0"
VICTIM = "192.168.1.101"
GATEWAY = "192.168.1.1"

PFSENSE_SSH = "admin@192.168.1.1"
SSH_KEY = "/home/owner/.ssh/id_ed25519"
LOG_OUTPUT_FILE = "mitm_detection_log.txt"
EXCEL_FILE = "mitm_detection.xlsx"
NUM_RUNS = 20
CHECK_INTERVAL = 2  # seconden tussen log checks

lines = []
date_now = 0

# === LOGGING ===
def write_log(message):
    timestamp = datetime.now()
    line = f"[{timestamp}] {message}"
    print(line)
    with open(LOG_OUTPUT_FILE, "a") as f:
        f.write(line + "\n")

# === START ETTERCAP ===
def start_ettercap():
    start_time = datetime.now()
    write_log("MITM attack gestart")

    process = subprocess.Popen([
    	"sudo",
        "ettercap",
        "-T",
        "-q",
        "-i", INTERFACE,
        "-M", "arp:remote",
        f"/{VICTIM}//",
        f"/{GATEWAY}//"
    ],
    stdout = subprocess.DEVNULL,
    stderr = subprocess.DEVNULL,
    stdin = subprocess.DEVNULL
    )
    return process, start_time

def parse_log_date(line):
    """
    Parse de timestamp van een pfSense system.log lijn.
    Verwacht formaat: 'Apr  7 14:22:14 pfSense arpwatch: flip ...'
    Geeft een datetime object van dit jaar terug.
    """
    try:
        # neem eerste 15 karakters: 'Apr  7 14:22:14'
        ts_str = line[:15]
        ts_dt = datetime.strptime(ts_str, "%b %d %H:%M:%S")
        # Voeg huidig jaar toe
        ts_dt = ts_dt.replace(year=datetime.now().year)
        if (log_dt.hour,log_dt.minute) >= (date_now.hour, start_time.minute):
        	return True
        else:
        	return False
    except Exception:
        return False


# === STOP ETTERCAP NETJES ===
def stop_ettercap(process):
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()

# === CHECK PFsense LOGS VIA SSH ===
def check_logs():
    ssh_command = [
        "ssh",
        "-i", SSH_KEY,
        "-o", "StrictHostKeyChecking=no",
        PFSENSE_SSH,
        "tail -n 100 /var/log/system.log"
    ]

    result = subprocess.run(
        ssh_command,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        write_log(f"SSH fout: {result.stderr.strip()}")
        return None

    for line in result.stdout.splitlines():
        temp = True
        if ("arpwatch" in line and ("flip" in line or "changed ethernet address" in line or "ethernet mismatch" in line)):
            for i in lines:
                if i == line:
                    temp = False
            if temp:
                lines.append(line)
                return line

    return None

# === MAIN FUNCTION ===
def main():
    # Maak Excel workbook
    wb = Workbook()
    ws = wb.active
    ws.title = "MITM Detection"
    ws.append(["Run", "Detectietijd (sec)", "ARPWatch Detectie"])

    for run in range(1, NUM_RUNS + 1):
        write_log(f"=== START RUN {run} ===")
        start_time = time.time_ns()
        process, start = start_ettercap()
        detected = False
        detection_time = None

        try:
            timeout = 60  # max tijd wachten per run
            start_loop = time.time()
            while time.time() - start_loop < timeout:
                log_line = check_logs()
                if log_line:
                    detection_time = time.time_ns()
                    delta_sec = (detection_time - start_time)
                    write_log(f"MITM gedetecteerd! ARPWatch LOG: {log_line} Detectietijd: {delta_sec:.2f} sec")
                    detected = True
                    break
                time.sleep(CHECK_INTERVAL)

            if not detected:
                delta_sec = None
                write_log("Geen detectie binnen timeout")

        finally:
            stop_ettercap(process)

        # Voeg data toe aan Excel
        ws.append([run, delta_sec, "Ja" if detected else "Nee"])
        wb.save(EXCEL_FILE)
        write_log(f"Run {run} opgeslagen in Excel\n")
        if detected:
        	time.sleep(60)

    write_log(f"Alle {NUM_RUNS} runs voltooid. Resultaten in {EXCEL_FILE}")

def start_detection():
	for i in range(100):
		check_logs()

if __name__ == "__main__":
    start_detection()
    main()

