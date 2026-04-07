import threading
import queue
import time
from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import deque
import logging

logging.basicConfig(filename='logs/sniffer.log', level=logging.ERROR, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

class PacketSniffer(threading.Thread):
    def __init__(self, packet_queue, interface=None, pcap_buffer_size=10000):
        super().__init__()
        self.packet_queue = packet_queue
        self.interface = interface
        self.running = True
        self.daemon = True
        self.raw_packets = deque(maxlen=pcap_buffer_size)   # store raw packets for PCAP
        self.lock = threading.Lock()

    def run(self):
        try:
            sniff(iface=self.interface, prn=self._process_packet, store=0, stop_filter=self._stop_filter)
        except Exception as e:
            logging.error(f"Sniffer error: {e}")

    def _process_packet(self, packet):
        if not self.running:
            return
        # Store raw packet for PCAP export
        with self.lock:
            self.raw_packets.append(packet)
        try:
            if IP in packet:
                src = packet[IP].src
                dst = packet[IP].dst
                proto = packet[IP].proto
                size = len(packet)
                ts = time.time()
                port = None
                if TCP in packet:
                    port = packet[TCP].dport
                    proto_name = "TCP"
                elif UDP in packet:
                    port = packet[UDP].dport
                    proto_name = "UDP"
                elif ICMP in packet:
                    proto_name = "ICMP"
                else:
                    proto_name = "OTHER"
                
                packet_info = {
                    'timestamp': ts,
                    'src_ip': src,
                    'dst_ip': dst,
                    'protocol': proto_name,
                    'port': port,
                    'size': size
                }
                self.packet_queue.put(packet_info)
        except Exception as e:
            logging.error(f"Error processing packet: {e}")

    def _stop_filter(self, packet):
        return not self.running

    def get_pcap_buffer(self):
        with self.lock:
            return list(self.raw_packets)

    def stop(self):
        self.running = False