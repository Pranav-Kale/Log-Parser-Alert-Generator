import re
import json
from datetime import datetime

log_path = "logs/auth.log"
alert_output = "alerts/alerts.json"

# Regex to detect failed login attempts
failed_login_pattern = re.compile(
    r"(?P<timestamp>\w{3} \d{1,2} \d{2}:\d{2}:\d{2}) .*sshd.*Failed password.* from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

alerts = []

def parse_log():
    with open(log_path, "r") as file:
        for line in file:
            match = failed_login_pattern.search(line)
            if match:
                alert = {
                    "type": "Failed Login Attempt",
                    "timestamp": match.group("timestamp"),
                    "ip_address": match.group("ip"),
                    "log": line.strip()
                }
                alerts.append(alert)

def save_alerts():
    with open(alert_output, "w") as f:
        json.dump(alerts, f, indent=4)
    print(f"[+] Alerts saved to {alert_output}")

if __name__ == "__main__":
    parse_log()
    save_alerts()
