import time
from collections import defaultdict, deque
import threading

class ThreatDetector:
    def __init__(self, time_window=10, port_scan_th=20, brute_th=10, ddos_th=100, burst_th=50):
        self.time_window = time_window
        self.port_scan_th = port_scan_th
        self.brute_th = brute_th
        self.ddos_th = ddos_th
        self.burst_th = burst_th
        self.src_ports = defaultdict(lambda: deque())
        self.src_packets = defaultdict(lambda: deque())
        self.lock = threading.Lock()

    def _clean_old(self, src_ip, current_time):
        while self.src_ports[src_ip] and self.src_ports[src_ip][0][0] < current_time - self.time_window:
            self.src_ports[src_ip].popleft()
        while self.src_packets[src_ip] and self.src_packets[src_ip][0][0] < current_time - self.time_window:
            self.src_packets[src_ip].popleft()

    def detect(self, packet_info):
        src = packet_info['src_ip']
        port = packet_info['port']
        ts = packet_info['timestamp']
        threats = []

        with self.lock:
            if port:
                self.src_ports[src].append((ts, port))
            self.src_packets[src].append((ts, packet_info['size']))
            self._clean_old(src, ts)

            unique_ports = {p for _, p in self.src_ports[src]}
            if len(unique_ports) >= self.port_scan_th:
                threats.append(('PORT_SCAN', min(100, 60 + len(unique_ports))))

            if port in [22, 23, 3389, 5900, 21] and len(self.src_packets[src]) >= self.brute_th:
                threats.append(('BRUTE_FORCE', min(100, 70 + len(self.src_packets[src]))))

            pkt_rate = len(self.src_packets[src]) / self.time_window
            if pkt_rate > self.ddos_th:
                threats.append(('DDoS_FLOOD', min(100, 80 + int(pkt_rate - self.ddos_th))))

            recent_sizes = [size for t, size in self.src_packets[src] if t > ts - 1]
            if len(recent_sizes) >= self.burst_th:
                threats.append(('BURST', min(100, 65 + len(recent_sizes))))

        return threats