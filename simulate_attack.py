import time

auth_logs = [
    "Failed password from 185.199.110.153\n",
    "Failed password from 103.21.244.12\n",
    "Failed password from 45.33.32.156\n",
    "Failed password from 91.198.174.192\n",
    "Failed password from 172.67.140.45\n"
]

web_logs = [
    "GET /admin from 192.0.2.45\n",
    "GET /login from 203.0.113.67\n",
    "GET /wp-admin from 198.51.100.23\n",
    "GET /phpmyadmin from 45.79.112.203\n",
    "GET /config from 104.26.10.78\n"
]

with open("logs/auth.log", "a") as a:
    for log in auth_logs:
        a.write(log)
        time.sleep(1)

with open("logs/web.log", "a") as w:
    for log in web_logs:
        w.write(log)
        time.sleep(1)

print("Attack simulation completed.")