# logging-hijacks
Log Analysis of Telnet session hijacking via MAC address spoofing using cowrie Honeypots

# Cowrie Traffic Monitor

## Overview
This package monitors network traffic and analyzes suspicious activities such as Telnet session hijacking and MAC address spoofing using the Cowrie Honeypot. It captures network packets, correlates suspicious IP and MAC addresses with Cowrie logs, and logs suspicious activities.

## Requirements
- Python 3
- Dependencies: `scapy`, `pyshark`, `requests`, `pandas`.
- Wireshark/tcpdump installed for packet capture
