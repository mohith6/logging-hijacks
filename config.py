
# Cowrie Honeypot API URL (replace with actual API endpoint)
COWRIE_API_URL = "http://localhost:8080/api/logs"  # Change based on your Cowrie setup

# Threshold for unusual behavior
IP_SUSPICIOUS_THRESHOLD = 5  # Number of occurrences to flag suspicious IP
MAC_SUSPICIOUS_THRESHOLD = 5  # Number of occurrences to flag suspicious MAC

# Network interface to capture traffic from
NETWORK_INTERFACE = "eth0"  # Change to your network interface name

# Logging configuration
LOG_FILE = "logs/session_hijacking.log"  # Log file for suspicious activity
SUSPICIOUS_CSV_FILE = "logs/suspicious_activities.csv"  # CSV to log suspicious activities
