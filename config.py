# Configuration file for MayOne Security Framework

# Detection thresholds
THRESHOLD = 0.6            # Risk threshold (0-1) above which action is taken
TIME_WINDOW = 10           # Time window in seconds for burst/scan detection
PORT_SCAN_THRESHOLD = 20   # Number of unique ports from one src in TIME_WINDOW
BRUTE_FORCE_THRESHOLD = 10 # Number of failed-like packets (e.g., TCP to port 22/3389)
DDoS_THRESHOLD = 100       # Packets per second from one src to trigger DDoS suspicion
BURST_THRESHOLD = 50       # Packets in 1 second from one src

# Response
AUTO_BLOCK = True          # Automatically block IP via Windows Firewall
LOG_LEVEL = "INFO"         # DEBUG, INFO, WARNING, ERROR
REPORT_INTERVAL = 600      # Seconds between automatic reports (10 minutes)

# Network interface to sniff (use None for default)
NETWORK_INTERFACE = None   # e.g., "Ethernet" or "Wi-Fi"

# Dashboard
DASHBOARD_HOST = "127.0.0.1"
DASHBOARD_PORT = 5000

# Database
DB_PATH = "database/security_events.db"

# Whitelisted private IP ranges (CIDR)
PRIVATE_RANGES = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
]

# GeoIP blocking
ENABLE_GEOIP_BLOCK = True          # Default state (can be toggled from dashboard)
GEOIP_DB_PATH = "geoip/GeoLite2-Country.mmdb"
HIGH_RISK_COUNTRIES = ["RU", "CN", "KP", "IR", "SY", "UA", "AF", "IQ", "LY", "SO"]

# PCAP export
PCAP_BUFFER_SIZE = 10000            # Max number of raw packets to keep