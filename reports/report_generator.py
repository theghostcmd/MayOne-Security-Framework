import json
import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.utils import simpleSplit

class ReportGenerator:
    def __init__(self, db):
        self.db = db
        self.report_dir = "reports"
        os.makedirs(self.report_dir, exist_ok=True)

    def _get_cursor(self):
        _, cursor = self.db._get_connection()
        return cursor

    def generate_report(self, reason="scheduled"):
        ts = datetime.now()
        base_name = f"security_report_{ts.strftime('%Y%m%d_%H%M%S')}"
        data = self._collect_data(ts)

        json_path = os.path.join(self.report_dir, base_name + ".json")
        with open(json_path, 'w') as f:
            json.dump(data, f, indent=2)

        txt_path = os.path.join(self.report_dir, base_name + ".txt")
        with open(txt_path, 'w') as f:
            f.write(self._format_text(data))

        pdf_path = os.path.join(self.report_dir, base_name + ".pdf")
        self._generate_pdf(data, pdf_path)

        cursor = self._get_cursor()
        cursor.execute('INSERT INTO reports (timestamp, report_path, type) VALUES (?, ?, ?)',
                       (ts.isoformat(), json_path, reason))
        self.db._get_connection()[0].commit()
        return json_path, txt_path, pdf_path

    def _collect_data(self, ts):
        events = self.db.get_recent_events(200)
        threats = self.db.get_threat_summary(24)
        blocked = self.db.get_blocked_ips()
        total_packets = len(events)
        unique_src = set(e[2] for e in events)
        return {
            "report_time": ts.isoformat(),
            "summary": {
                "total_events": total_packets,
                "unique_sources": len(unique_src),
                "threats_detected": len([e for e in events if e[7] is not None]),
                "blocked_ips": len(blocked)
            },
            "threat_breakdown": [{"type": t[0], "count": t[1], "avg_risk": t[2]} for t in threats],
            "blocked_ips_list": [{"ip": b[0], "time": b[1], "reason": b[2]} for b in blocked],
            "top_suspicious": self._get_top_ips(events),
            "recommendations": self._generate_recs(threats, len(blocked))
        }

    def _get_top_ips(self, events, n=5):
        freq = {}
        for e in events:
            ip = e[2]
            freq[ip] = freq.get(ip, 0) + 1
        sorted_ips = sorted(freq.items(), key=lambda x: x[1], reverse=True)[:n]
        return [{"ip": ip, "packets": cnt} for ip, cnt in sorted_ips]

    def _generate_recs(self, threats, blocked_count):
        recs = []
        if any(t[0] == "PORT_SCAN" for t in threats):
            recs.append("Enable port knocking or move SSH/RDP to non-standard ports.")
        if any(t[0] == "BRUTE_FORCE" for t in threats):
            recs.append("Enforce strong passwords and consider account lockout policies.")
        if blocked_count > 10:
            recs.append("Review blocked IP list; consider using an IP reputation feed.")
        if not recs:
            recs.append("No immediate action required. Continue monitoring.")
        return recs

    def _format_text(self, data):
        lines = []
        lines.append("="*60)
        lines.append(f"MayOne Security Report - {data['report_time']}")
        lines.append("="*60)
        lines.append("\nSUMMARY")
        for k,v in data['summary'].items():
            lines.append(f"  {k}: {v}")
        lines.append("\nTHREAT BREAKDOWN")
        for t in data['threat_breakdown']:
            lines.append(f"  {t['type']}: {t['count']} events, avg risk {t['avg_risk']:.1f}")
        lines.append("\nBLOCKED IPs")
        for b in data['blocked_ips_list'][:10]:
            lines.append(f"  {b['ip']} - {b['reason']} (since {b['time']})")
        lines.append("\nRECOMMENDATIONS")
        for r in data['recommendations']:
            lines.append(f"  - {r}")
        return "\n".join(lines)

    def _generate_pdf(self, data, path):
        c = canvas.Canvas(path, pagesize=letter)
        width, height = letter
        y = height - 50
        c.drawString(50, y, f"MayOne Security Report - {data['report_time']}")
        y -= 30
        c.drawString(50, y, "Summary")
        y -= 20
        for k,v in data['summary'].items():
            c.drawString(70, y, f"{k}: {v}")
            y -= 15
        y -= 10
        c.drawString(50, y, "Top Recommendations")
        y -= 20
        for rec in data['recommendations'][:3]:
            lines = simpleSplit(rec, "Helvetica", 12, width-100)
            for line in lines:
                c.drawString(70, y, f"- {line}")
                y -= 15
        c.save()