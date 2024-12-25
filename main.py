import pyshark
import scapy.all as scapy
import requests
import pandas as pd
import logging
from collections import defaultdict
from time import sleep
from config import *

# Configure logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO)

# Stores for tracking suspicious IPs and MACs
suspicious_ips = defaultdict(int)
suspicious_macs = defaultdict(int)
ip_mac_history = defaultdict(list)


def monitor_traffic(interface=NETWORK_INTERFACE, packet_count=1000):
    """ Monitor network traffic and analyze suspicious IP and MAC combinations. """
    capture = pyshark.LiveCapture(interface=interface)

    print(f"Monitoring network traffic on {interface}...")

    # Capture specified number of packets
    capture.sniff(packet_count=packet_count)

    for packet in capture:
        try:
            if 'IP' in packet:
                ip_src = packet.ip.src
                ip_dst = packet.ip.dst
                mac_src = packet.eth.src
                mac_dst = packet.eth.dst

                # Increase suspicious counters
                suspicious_ips[ip_src] += 1
                suspicious_ips[ip_dst] += 1
                suspicious_macs[mac_src] += 1
                suspicious_macs[mac_dst] += 1

                # Log the packet info
                logging.info(f"Packet captured: {ip_src} -> {ip_dst}, MAC: {mac_src} -> {mac_dst}")
                track_ip_mac_changes(ip_src, mac_src)

        except AttributeError as e:
            # Some packets might not have IP or MAC headers, skip them
            continue

    analyze_suspicious_traffic()


def track_ip_mac_changes(ip, mac):
    """ Track changes in IP-MAC associations to detect spoofing. """
    if ip in ip_mac_history:
        # Check if MAC has changed recently
        last_macs = ip_mac_history[ip]
        if len(last_macs) > 3 and all(mac != last_mac for last_mac in last_macs[-3:]):
            logging.warning(f"IP {ip} has unusual MAC changes: {last_macs[-3:]} -> {mac}")
        ip_mac_history[ip].append(mac)
    else:
        ip_mac_history[ip] = [mac]


def analyze_suspicious_traffic():
    """ Analyze captured traffic for unusual IP and MAC address combinations. """
    suspicious_ip_list = [ip for ip, count in suspicious_ips.items() if count > IP_SUSPICIOUS_THRESHOLD]
    suspicious_mac_list = [mac for mac, count in suspicious_macs.items() if count > MAC_SUSPICIOUS_THRESHOLD]

    if suspicious_ip_list:
        logging.info(f"Suspicious IPs detected: {suspicious_ip_list}")

    if suspicious_mac_list:
        logging.info(f"Suspicious MAC addresses detected: {suspicious_mac_list}")

    correlate_with_cowrie(suspicious_ip_list, suspicious_mac_list)


def correlate_with_cowrie(suspicious_ips, suspicious_macs):
    """ Correlate suspicious IP and MAC addresses with Cowrie logs. """
    try:
        response = requests.get(COWRIE_API_URL)
        if response.status_code == 200:
            cowrie_logs = response.json()
            for log in cowrie_logs:
                ip_address = log.get("src_ip", None)
                mac_address = log.get("src_mac", None)
                if ip_address in suspicious_ips or mac_address in suspicious_macs:
                    logging.warning(f"Suspicious activity detected: {log}")
                    # Optionally, store the result in a file or database
                    pd.DataFrame([log]).to_csv(SUSPICIOUS_CSV_FILE, mode='a', header=False)
        else:
            logging.error(f"Failed to fetch Cowrie logs. Status code: {response.status_code}")
    except requests.RequestException as e:
        logging.error(f"Error connecting to Cowrie API: {str(e)}")


def monitor_arp_spoofing(interface=NETWORK_INTERFACE):
    """ Monitor ARP packets for MAC address spoofing. """
    print(f"Monitoring ARP traffic on {interface} for MAC address spoofing...")

    # Set the sniff filter to ARP packets
    scapy.sniff(iface=interface, prn=lambda packet: check_for_mac_address_spoofing(packet), store=0)


def check_for_mac_address_spoofing(packet):
    """ Check if there's a MAC address spoofing attempt. """
    if 'ARP' in packet:
        # In ARP packets, we can detect IP-to-MAC address mapping
        ip_src = packet.arp.psrc
        mac_src = packet.arp.hwsrc
        ip_dst = packet.arp.pdst
        mac_dst = packet.arp.hwdst

        # Check if this mapping is consistent with the previously seen IP and MAC pairs
        if ip_src in suspicious_ips and mac_src not in suspicious_macs:
            logging.warning(f"Possible MAC Spoofing detected: {ip_src} -> {mac_src}")
            suspicious_macs[mac_src] += 1
            suspicious_ips[ip_src] += 1
            return True
    return False


def detect_brute_force(cowrie_logs):
    """ Detect brute force attacks based on failed login attempts. """
    ip_attempts = defaultdict(int)

    for log in cowrie_logs:
        if 'Failed password' in log.get('message', ''):
            ip_attempts[log['src_ip']] += 1

    for ip, attempts in ip_attempts.items():
        if attempts > 5:  # Adjust this threshold as needed
            logging.warning(f"Possible brute force detected from IP: {ip} with {attempts} failed attempts.")


def main():
    # Run network traffic monitoring in a separate thread or process
    monitor_traffic()

    # Run ARP spoofing detection
    monitor_arp_spoofing()


if __name__ == "__main__":
    main()
