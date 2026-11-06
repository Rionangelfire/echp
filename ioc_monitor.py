import os
import re
import time
import json
import smtplib
from datetime import datetime
from email.message import EmailMessage
import socket

# Email Configuration
sender_email = "Robertlouisbostick@yahoo.com"
# SECURITY: the Yahoo app password is NOT stored in this file.
# Set it as an environment variable: YAHOO_APP_PASSWORD
# (The value pasted in chat on Nov 5, 2026 was removed here and must be rotated.)
sender_password = os.environ.get("YAHOO_APP_PASSWORD", "")
recipient_email = "Robertlouisbostick@yahoo.com"
smtp_server = "smtp.mail.yahoo.com"
smtp_port = 587

# Known IOCs
# NOTE (Nov 5, 2026): these are placeholder/example values, not live threat intel.
# 203.0.113.45 is TEST-NET-3 documentation space; 5d41402abc4b2a76b9719d911017c592
# is the MD5 of "hello". Replace with real IOCs before relying on this monitor.
known_iocs = {
    "ips": {"203.0.113.45"},
    "domains": {"bad-domain.com", "evil-site.net"},
    "hashes": {"5d41402abc4b2a76b9719d911017c592"}
}

ioc_categories = {
    "203.0.113.45": "spam",
    "bad-domain.com": "spam",
    "evil-site.net": "malware",
    "5d41402abc4b2a76b9719d911017c592": "botnet"
}

ioc_scores = {
    "203.0.113.45": 6,
    "bad-domain.com": 1,
    "evil-site.net": 1,
    "5d41402abc4b2a76b9719d911017c592": 1
}

# Regex patterns
ip_regex = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
domain_regex = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
hash_regex = re.compile(r'\b[a-fA-F0-9]{32}\b')

log_directory = "logs"
alert_log_file = "ioc_alerts.log"
processed_files = set()

def send_email_alert(ioc, source_file):
    msg = EmailMessage()
    msg['Subject'] = f"Threat Alert: IOC Detected in {source_file}"
    msg['From'] = sender_email
    msg['To'] = recipient_email

    body = f"""
    A new threat has been detected!

    Threat Details:
    - Type: {ioc['type']}
    - Value: {ioc['value']}
    - Category: {ioc['category']}
    - Score: {ioc['score']}

    Source File: {source_file}
    Timestamp: {datetime.now().isoformat()}
    """
    msg.set_content(body)

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(msg)
        print(f"Email alert sent for {ioc['value']}")
    except Exception as e:
        print(f"Email failed: {e}")

def send_to_siem(log_entry):
    print(f"SIEM Alert: {json.dumps(log_entry)}")

def parse_log_data(log_data):
    ips = ip_regex.findall(log_data)
    domains = domain_regex.findall(log_data)
    hashes = hash_regex.findall(log_data)
    return set(ips), set(domains), set(hashes)

# TODO (Nov 5, 2026): match_iocs() is called by receive_syslog() below but was
# never defined in the pasted source — the script crashes with a NameError on
# the first syslog message. It should take (ips, domains, hashes) and return a
# list of dicts with keys: type, value, category, score, using known_iocs,
# ioc_categories and ioc_scores above.
def match_iocs(ips, domains, hashes):
    matched = []
    for ip in ips:
        if ip in known_iocs["ips"]:
            matched.append({"type": "ip", "value": ip,
                            "category": ioc_categories.get(ip, "unknown"),
                            "score": ioc_scores.get(ip, 0)})
    for domain in domains:
        if domain in known_iocs["domains"]:
            matched.append({"type": "domain", "value": domain,
                            "category": ioc_categories.get(domain, "unknown"),
                            "score": ioc_scores.get(domain, 0)})
    for h in hashes:
        if h.lower() in known_iocs["hashes"]:
            matched.append({"type": "hash", "value": h,
                            "category": ioc_categories.get(h.lower(), "unknown"),
                            "score": ioc_scores.get(h.lower(), 0)})
    return matched

def log_alerts(matched_iocs, source_file):
    timestamp = datetime.now().isoformat()
    with open(alert_log_file, 'a') as log_file:
        for ioc in matched_iocs:
            log_entry = {
                "event_type": "ioc_alert",
                "timestamp": timestamp,
                "source_file": source_file,
                "ioc_type": ioc['type'],
                "ioc_value": ioc['value'],
                "score": ioc['score'],
                "category": ioc['category']
            }
            log_file.write(json.dumps(log_entry) + "\n")

            send_email_alert(ioc, source_file)
            send_to_siem(log_entry)

def receive_syslog():
    # UDP socket for receiving Syslog messages
    UDP_IP = "0.0.0.0"  # Listen on all available interfaces
    UDP_PORT = 514      # Default Syslog port

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))

    print(f"Listening for Syslog messages on UDP port {UDP_PORT}...")

    while True:
        data, addr = sock.recvfrom(4096)  # Buffer size
        log_data = data.decode('utf-8', errors='ignore')
        print(f"Received log from {addr}: {log_data}")

        # Process the received log data
        ips, domains, hashes = parse_log_data(log_data)
        matched_iocs = match_iocs(ips, domains, hashes)

        if matched_iocs:
            log_alerts(matched_iocs, f"Syslog from {addr[0]}")

if __name__ == "__main__":
    receive_syslog()
