# AutoDefender - Rule Based Intrusion Detection System

from collections import defaultdict

# File paths
AUTH_LOG = "logs/auth.log"
WEB_LOG = "logs/web.log"
BLOCKED_IPS_FILE = "output/blocked_ips.txt"
ALERTS_FILE = "output/alerts.log"

# Detection thresholds
FAILED_LOGIN_THRESHOLD = 3
SQLI_THRESHOLD = 2

failed_login_count = defaultdict(int)
sqli_count = defaultdict(int)
blocked_ips = set()

def log_alert(message):
    with open(ALERTS_FILE, "a") as alert:
        alert.write(message + "\n")

def block_ip(ip):
    if ip not in blocked_ips:
        blocked_ips.add(ip)
        with open(BLOCKED_IPS_FILE, "a") as f:
            f.write(ip + "\n")
        log_alert(f"[ALERT] IP BLOCKED: {ip}")

def analyze_auth_log():
    with open(AUTH_LOG, "r") as file:
        for line in file:
            if "FAILED_LOGIN" in line:
                ip = line.split("IP=")[1].split()[0]
                failed_login_count[ip] += 1

                if failed_login_count[ip] >= FAILED_LOGIN_THRESHOLD:
                    block_ip(ip)

def analyze_web_log():
    with open(WEB_LOG, "r") as file:
        for line in file:
            if "OR '1'='1" in line:
                ip = line.split("IP=")[1].split()[0]
                sqli_count[ip] += 1

                if sqli_count[ip] >= SQLI_THRESHOLD:
                    block_ip(ip)

def main():
    analyze_auth_log()
    analyze_web_log()

    print("AutoDefender Scan Completed")
    print(f"Total Blocked IPs: {len(blocked_ips)}")

if __name__ == "__main__":
    main()