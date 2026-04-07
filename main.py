#!/usr/bin/env python3
import threading
import queue
import time
import logging
import signal
import sys
import ipaddress
from config import *
from database.db import Database
from monitor.packet_sniffer import PacketSniffer
from detection.threat_detector import ThreatDetector
from ai.anomaly_model import AnomalyModel
from ai.risk_scoring import RiskScorer
from response.block_ip import block_ip_windows
from reports.report_generator import ReportGenerator
from dashboard.app import run_dashboard
from geoip.blocker import GeoIPBlocker

logging.basicConfig(
    filename='logs/system.log',
    level=getattr(logging, LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
logging.getLogger('').addHandler(console)

# Global variable that can be toggled from dashboard
geoip_enabled = ENABLE_GEOIP_BLOCK

def is_private_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
        for cidr in PRIVATE_RANGES:
            if addr in ipaddress.ip_network(cidr):
                return True
        return False
    except:
        return False

class MayOneEngine:
    def __init__(self):
        self.packet_queue = queue.Queue(maxsize=10000)
        self.db = Database()
        self.sniffer = PacketSniffer(self.packet_queue, NETWORK_INTERFACE, PCAP_BUFFER_SIZE)
        self.detector = ThreatDetector(TIME_WINDOW, PORT_SCAN_THRESHOLD,
                                       BRUTE_FORCE_THRESHOLD, DDoS_THRESHOLD, BURST_THRESHOLD)
        self.anomaly_model = AnomalyModel()
        self.scorer = RiskScorer()
        self.reporter = ReportGenerator(self.db)
        self.geoip = GeoIPBlocker() if ENABLE_GEOIP_BLOCK else None
        self.running = True
        self.last_report_time = time.time()
        self.recently_blocked = set()

    def start(self):
        logging.info("Starting MayOne Security Framework")
        self.sniffer.start()
        dash_thread = threading.Thread(target=run_dashboard, args=(DASHBOARD_HOST, DASHBOARD_PORT, self.sniffer), daemon=True)
        dash_thread.start()
        while self.running:
            try:
                packet = self.packet_queue.get(timeout=1)
                self.process_packet(packet)
            except queue.Empty:
                self.check_auto_report()
                continue
            except Exception as e:
                logging.error(f"Main loop error: {e}", exc_info=True)

    def process_packet(self, packet):
        global geoip_enabled
        src_ip = packet['src_ip']
        
        # GeoIP blocking check (if enabled)
        if geoip_enabled and self.geoip and not is_private_ip(src_ip):
            if self.geoip.is_high_risk(src_ip):
                logging.info(f"GeoIP high-risk country detected: {src_ip}")
                if AUTO_BLOCK and src_ip not in self.recently_blocked:
                    if block_ip_windows(src_ip, "GeoIP high-risk country"):
                        self.db.insert_blocked_ip(src_ip, "GeoIP auto-block")
                        self.recently_blocked.add(src_ip)
                        action = "GEO_BLOCKED"
                        self.db.insert_event(src_ip, packet['dst_ip'], packet['protocol'],
                                             packet['port'], packet['size'], "GEOIP_RISK", 90, action)
                        self.db.insert_threat(src_ip, "GEOIP_RISK", 90, f"Country: high-risk")
                        return  # skip further processing

        # Normal AI + rule detection
        anomaly_score = self.anomaly_model.predict_anomaly_score(packet)
        rule_threats = self.detector.detect(packet)
        risk = self.scorer.compute_risk(rule_threats, anomaly_score)
        threat_level = self.scorer.threat_level(risk)
        action = None

        if risk >= THRESHOLD * 100 and AUTO_BLOCK and not is_private_ip(src_ip):
            if src_ip not in self.recently_blocked:
                if block_ip_windows(src_ip, f"{threat_level} risk {risk}"):
                    self.db.insert_blocked_ip(src_ip, f"{threat_level} risk")
                    self.recently_blocked.add(src_ip)
                    action = "BLOCKED"

        threat_type = rule_threats[0][0] if rule_threats else None
        self.db.insert_event(
            src_ip, packet['dst_ip'], packet['protocol'],
            packet['port'], packet['size'], threat_type, risk, action
        )
        if threat_type or anomaly_score > 0.3:
            self.db.insert_threat(src_ip, threat_type or "ANOMALY", risk,
                                  f"Anomaly={anomaly_score:.2f}")

        if threat_level == "CRITICAL":
            logging.warning(f"CRITICAL threat from {src_ip} - generating emergency report")
            threading.Thread(target=self.reporter.generate_report, args=("critical_threat",)).start()

        self.anomaly_model.add_packet(packet)

    def check_auto_report(self):
        if time.time() - self.last_report_time >= REPORT_INTERVAL:
            logging.info("Generating scheduled report")
            self.reporter.generate_report("scheduled")
            self.last_report_time = time.time()

    def shutdown(self):
        logging.info("Shutting down MayOne Security Framework")
        self.running = False
        self.sniffer.stop()
        self.db.close()
        sys.exit(0)

if __name__ == "__main__":
    engine = MayOneEngine()
    signal.signal(signal.SIGINT, lambda sig, frame: engine.shutdown())
    engine.start()