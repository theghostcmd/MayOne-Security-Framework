#!/usr/bin/env python3
import os
import sys
sys.path.append('.')
from database.db import Database
from detection.threat_detector import ThreatDetector
from ai.risk_scoring import RiskScorer
from reports.report_generator import ReportGenerator

def test_db():
    db = Database()
    db.insert_event("192.168.1.100", "8.8.8.8", "TCP", 443, 1500, "TEST", 50, None)
    events = db.get_recent_events()
    assert len(events) >= 1
    print("[OK] Database works")

def test_detector():
    det = ThreatDetector(time_window=10, port_scan_th=3)
    packets = [
        {'src_ip': '1.2.3.4', 'port': 80, 'timestamp': 100},
        {'src_ip': '1.2.3.4', 'port': 81, 'timestamp': 101},
        {'src_ip': '1.2.3.4', 'port': 82, 'timestamp': 102},
        {'src_ip': '1.2.3.4', 'port': 83, 'timestamp': 103},
    ]
    for p in packets:
        threats = det.detect(p)
    assert any(t[0]=='PORT_SCAN' for t in threats)
    print("[OK] Threat detector works")

def test_risk_scorer():
    scorer = RiskScorer()
    risk = scorer.compute_risk([('PORT_SCAN', 80)], 0.5)
    assert 0 <= risk <= 100
    print("[OK] Risk scoring works")

def test_report(db):
    gen = ReportGenerator(db)
    paths = gen.generate_report("test")
    for p in paths:
        assert os.path.exists(p)
    print("[OK] Report generation works")

if __name__ == "__main__":
    test_db()
    test_detector()
    test_risk_scorer()
    db = Database()
    test_report(db)
    print("All tests passed.")