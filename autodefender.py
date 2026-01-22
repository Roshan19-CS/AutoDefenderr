import re
import time
from pathlib import Path

# File paths
AUTH_LOG = "logs/auth.log"
WEB_LOG = "logs/web.log"
ALERT_LOG = "output/alerts.log"
BLOCKED_IPS_FILE = "output/blocked_ips.txt"

Path("output").mkdir(exist_ok=True)

# Load blocked IPs
blocked_ips = set()
if Path(BLOCKED_IPS_FILE).exists():
    with open(BLOCKED_IPS_FILE, "r") as f:
        for line in f:
            blocked_ips.add(line.strip())

# Regex for IP address
ip_pattern = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

def block_ip(ip):
    global blocked_ips
    if ip not in blocked_ips:
        blocked_ips.add(ip)

        with open(BLOCKED_IPS_FILE, "a") as f:
            f.write(ip + "\n")

        with open(ALERT_LOG, "a") as f:
            f.write(f"[ALERT] IP BLOCKED: {ip}\n")

        print(f"[+] BLOCKED IP: {ip}")

def analyze_log(file_path, keywords):
    if not Path(file_path).exists():
        return

    with open(file_path, "r") as log:
        for line in log:
            for keyword in keywords:
                if keyword.lower() in line.lower():
                    ips = ip_pattern.findall(line)
                    for ip in ips:
                        block_ip(ip)

def main():
    print("[*] AutoDefender started...")

    while True:
        analyze_log(AUTH_LOG, ["failed", "invalid", "error"])
        analyze_log(WEB_LOG, ["scan", "nmap", "attack", "exploit"])
        time.sleep(5)

if __name__ == "__main__":
    main()