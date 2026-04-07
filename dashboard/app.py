from flask import Flask, render_template_string, jsonify, request, send_file
import sys
import os
import io
from datetime import datetime
from collections import Counter
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
from reportlab.lib.units import inch
from scapy.utils import wrpcap
import tempfile

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.db import Database
from response.block_ip import block_ip_windows, unblock_ip_windows
from geoip.blocker import GeoIPBlocker

app = Flask(__name__)
db = None
pcap_sniffer = None
geoip = None
geoip_available = False

# ---------- PDF Helpers ----------
def add_page_number(c, page_num):
    c.saveState()
    c.setFont("Helvetica", 8)
    c.drawString(letter[0] - 80, 30, f"Page {page_num}")
    c.restoreState()

def draw_header(c, title, subtitle=""):
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, letter[1] - 50, title)
    c.setFont("Helvetica", 10)
    c.drawString(50, letter[1] - 70, subtitle)
    c.line(50, letter[1] - 80, letter[0] - 50, letter[1] - 80)

def draw_watermark(c, logo_path):
    if os.path.exists(logo_path):
        try:
            img = ImageReader(logo_path)
            c.saveState()
            c.setFillAlpha(0.2)
            c.drawImage(img, letter[0]/2 - 1.5*inch, letter[1]/2 - 1.5*inch,
                        width=3*inch, height=3*inch, mask='auto', preserveAspectRatio=True)
            c.restoreState()
        except:
            pass

def generate_blocked_ips_pdf():
    blocked = db.get_blocked_ips()
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    logo_path = os.path.join(os.path.dirname(__file__), 'static', 'logo.png')
    page_num = 1

    draw_watermark(c, logo_path)
    draw_header(c, "MayOne Security Framework", "Blocked IP Addresses Report")
    y = letter[1] - 110
    c.drawString(50, y, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    y -= 20
    c.drawString(50, y, f"Total Blocked IPs: {len(blocked)}")
    y -= 40

    c.setFont("Helvetica-Bold", 10)
    c.drawString(50, y, "IP Address")
    c.drawString(160, y, "Blocked Since")
    c.drawString(300, y, "Reason")
    c.setFont("Helvetica", 10)
    y -= 20

    for ip, block_time, reason in blocked:
        if y < 80:
            draw_watermark(c, logo_path)
            add_page_number(c, page_num)
            c.showPage()
            page_num += 1
            draw_header(c, "MayOne Security Framework (cont.)", "Blocked IPs")
            y = letter[1] - 110
            c.setFont("Helvetica-Bold", 10)
            c.drawString(50, y, "IP Address")
            c.drawString(160, y, "Blocked Since")
            c.drawString(300, y, "Reason")
            c.setFont("Helvetica", 10)
            y -= 20
        reason_short = reason[:60] + "..." if len(reason) > 60 else reason
        c.drawString(50, y, ip)
        c.drawString(160, y, block_time[:19])
        c.drawString(300, y, reason_short)
        y -= 20

    add_page_number(c, page_num)
    c.save()
    buffer.seek(0)
    return buffer

def generate_all_ips_pdf():
    events = db.get_recent_events(limit=1000)
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    logo_path = os.path.join(os.path.dirname(__file__), 'static', 'logo.png')
    page_num = 1

    draw_watermark(c, logo_path)
    draw_header(c, "MayOne Security Framework", "Complete IP Traffic Log")
    y = letter[1] - 110
    c.drawString(50, y, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    y -= 20
    c.drawString(50, y, f"Total Events: {len(events)}")
    y -= 40

    headers = ["Timestamp", "Src IP", "Dst IP", "Proto", "Port", "Size", "Threat", "Risk"]
    col_widths = [100, 80, 80, 40, 40, 50, 70, 40]
    c.setFont("Helvetica-Bold", 8)
    x = 50
    for i, h in enumerate(headers):
        c.drawString(x, y, h)
        x += col_widths[i]
    c.setFont("Helvetica", 8)
    y -= 15

    for ev in events:
        if y < 80:
            draw_watermark(c, logo_path)
            add_page_number(c, page_num)
            c.showPage()
            page_num += 1
            draw_header(c, "MayOne Security Framework (cont.)", "IP Traffic Log")
            y = letter[1] - 110
            c.setFont("Helvetica-Bold", 8)
            x = 50
            for i, h in enumerate(headers):
                c.drawString(x, y, h)
                x += col_widths[i]
            c.setFont("Helvetica", 8)
            y -= 15
        ts = ev[1][:19] if len(ev[1]) > 19 else ev[1]
        src = ev[2][:15]
        dst = ev[3][:15]
        proto = ev[4][:4]
        port = str(ev[5]) if ev[5] else ""
        size = str(ev[6])
        threat = ev[7] or "Normal"
        risk = str(ev[8]) if ev[8] else "0"
        x = 50
        c.drawString(x, y, ts); x += col_widths[0]
        c.drawString(x, y, src); x += col_widths[1]
        c.drawString(x, y, dst); x += col_widths[2]
        c.drawString(x, y, proto); x += col_widths[3]
        c.drawString(x, y, port); x += col_widths[4]
        c.drawString(x, y, size); x += col_widths[5]
        c.drawString(x, y, threat); x += col_widths[6]
        c.drawString(x, y, risk)
        y -= 12

    add_page_number(c, page_num)
    c.save()
    buffer.seek(0)
    return buffer

# ---------- HTML Template (with GeoIP warning and conditional toggle) ----------
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>MayOne Security Framework</title>
    <meta charset="UTF-8">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * { box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; background: #0a0f1e; color: #eef4ff; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; }
        .header { display: flex; align-items: center; gap: 20px; margin-bottom: 30px; border-bottom: 2px solid #2a3f6e; padding-bottom: 15px; }
        .logo { height: 60px; width: auto; }
        h1 { margin: 0; font-size: 2rem; background: linear-gradient(135deg, #ff6b6b, #4ecdc4); -webkit-background-clip: text; background-clip: text; color: transparent; }
        .subtitle { color: #8e9aaf; margin-top: 5px; }
        .card { background: #141b2b; border-radius: 16px; padding: 20px; margin-bottom: 25px; box-shadow: 0 8px 20px rgba(0,0,0,0.3); border: 1px solid #2a3f6e; }
        .card h2 { margin-top: 0; color: #4ecdc4; font-size: 1.5rem; }
        .stats-grid { display: flex; gap: 20px; flex-wrap: wrap; }
        .stat-box { background: #0f172a; padding: 15px 25px; border-radius: 12px; flex: 1; min-width: 150px; text-align: center; border-left: 4px solid #4ecdc4; }
        .stat-number { font-size: 2rem; font-weight: bold; color: #ffd966; }
        .chart-container { display: flex; gap: 20px; flex-wrap: wrap; }
        .chart-box { flex: 1; min-width: 250px; background: #0f172a; border-radius: 12px; padding: 15px; }
        canvas { max-height: 300px; width: 100%; }
        table { width: 100%; border-collapse: collapse; }
        th, td { text-align: left; padding: 12px; border-bottom: 1px solid #2a3f6e; }
        th { background: #1e2a3a; color: #4ecdc4; }
        .critical { color: #ff6b6b; font-weight: bold; }
        .high { color: #ffa64d; }
        .medium { color: #ffd966; }
        .form-group { display: flex; gap: 10px; flex-wrap: wrap; align-items: flex-end; }
        .form-field { flex: 1; }
        label { display: block; font-size: 0.8rem; margin-bottom: 5px; color: #8e9aaf; }
        input, textarea { width: 100%; padding: 10px; background: #0f172a; border: 1px solid #2a3f6e; border-radius: 8px; color: #eef4ff; font-size: 0.9rem; }
        button { background: #4ecdc4; color: #0a0f1e; border: none; padding: 10px 20px; border-radius: 8px; cursor: pointer; font-weight: bold; transition: 0.2s; }
        button.danger { background: #ff6b6b; }
        button.secondary { background: #2a3f6e; color: white; }
        button:hover { opacity: 0.85; transform: translateY(-2px); }
        .alert { padding: 10px; border-radius: 8px; margin-bottom: 15px; display: none; }
        .alert-success { background: #2e7d64; color: white; }
        .alert-error { background: #b91c1c; color: white; }
        .toolbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; flex-wrap: wrap; gap: 10px; }
        .warning { background: #ffaa44; color: #0a0f1e; padding: 10px 15px; border-radius: 8px; margin-bottom: 20px; font-weight: bold; }
        footer { text-align: center; margin-top: 30px; font-size: 0.8rem; color: #5a6e8a; }
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <img src="/static/logo.png" alt="MayOne Logo" class="logo" onerror="this.style.display='none'">
        <div>
            <h1>🛡️ MayOne Security Framework</h1>
            <div class="subtitle">AI‑powered Intrusion Detection & Response</div>
        </div>
    </div>
    <div id="alertBox" class="alert"></div>
    <div id="geoipWarning" class="warning" style="display: none;">
        ⚠️ GeoIP database not found. Download GeoLite2-Country.mmdb and place it in the 'geoip/' folder to enable country lookup and automatic blocking.
    </div>
    <div class="card">
        <h2>📊 Live Statistics</h2>
        <div class="stats-grid">
            <div class="stat-box"><div class="stat-number" id="totalEvents">0</div><div>Total Events</div></div>
            <div class="stat-box"><div class="stat-number" id="uniqueSrc">0</div><div>Unique Sources</div></div>
            <div class="stat-box"><div class="stat-number" id="blockedCount">0</div><div>Blocked IPs</div></div>
        </div>
    </div>
    <div class="card">
        <h2>📡 Traffic Analysis</h2>
        <div class="chart-container">
            <div class="chart-box"><h3>Protocol Distribution</h3><canvas id="protocolChart"></canvas></div>
            <div class="chart-box"><h3>Top 5 Ports</h3><canvas id="portChart"></canvas></div>
        </div>
    </div>
    <div class="card">
        <h2>🚨 Recent Threats</h2>
        <div style="overflow-x: auto;">
            <table id="threatsTable">
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Source IP</th>
                        <th>Country</th>
                        <th>Protocol</th>
                        <th>Dest Port</th>
                        <th>Threat Type</th>
                        <th>Risk</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody id="threatsBody">
                    <tr><td colspan="8">Loading...</td></tr>
                </tbody>
            </table>
        </div>
    </div>
    <div class="card">
        <div class="toolbar">
            <h2>🚫 Blocked IPs & Manual Control</h2>
            <div style="display: flex; gap: 15px; align-items: center;">
                <label id="geoipLabel" style="display: inline-flex; align-items: center; gap: 8px; background: #1e2a3a; padding: 5px 12px; border-radius: 20px;">
                    🌍 GeoIP Blocking
                    <input type="checkbox" id="geoipToggle" style="width: 18px; height: 18px; margin: 0;">
                </label>
                <button id="downloadBlockedPdfBtn" class="secondary">📄 Blocked IPs (PDF)</button>
                <button id="downloadAllPdfBtn" class="secondary">📊 All IP Logs (PDF)</button>
                <button id="downloadPcapBtn" class="secondary">📦 Download PCAP</button>
            </div>
        </div>
        <div class="form-group" style="margin-bottom: 25px;">
            <div class="form-field"><label>IP Address to Block</label><input type="text" id="blockIp" placeholder="e.g., 203.0.113.5"></div>
            <div class="form-field"><label>Reason (optional)</label><input type="text" id="blockReason" placeholder="Manual block"></div>
            <button id="blockBtn">➕ Block IP</button>
        </div>
        <div style="overflow-x: auto;">
            <table id="blockedTable">
                <thead>
                    <tr><th>IP Address</th><th>Blocked Since</th><th>Reason</th><th>Action</th></tr>
                </thead>
                <tbody id="blockedBody">
                    <tr><td colspan="4">Loading...</td></tr>
                </tbody>
            </table>
        </div>
    </div>
    <footer>MayOne Security Framework — Real‑time monitoring | Auto‑refresh every 3s</footer>
</div>

<script>
    let protocolChart, portChart;
    let geoipAvailable = {{ geoip_available|tojson }};

    if (!geoipAvailable) {
        document.getElementById('geoipWarning').style.display = 'block';
        document.getElementById('geoipToggle').disabled = true;
        document.getElementById('geoipLabel').style.opacity = '0.6';
    }

    function showAlert(message, type) {
        const alertDiv = document.getElementById('alertBox');
        alertDiv.textContent = message;
        alertDiv.className = `alert alert-${type}`;
        alertDiv.style.display = 'block';
        setTimeout(() => { alertDiv.style.display = 'none'; }, 4000);
    }

    async function fetchStats() {
        try {
            const res = await fetch('/api/stats');
            const data = await res.json();
            document.getElementById('totalEvents').innerText = data.total_events;
            document.getElementById('uniqueSrc').innerText = data.unique_src;
            document.getElementById('blockedCount').innerText = data.blocked_count;
        } catch(e) { console.error('Stats error', e); }
    }

    async function fetchTrafficStats() {
        try {
            const res = await fetch('/api/traffic_stats');
            const data = await res.json();
            if (protocolChart) protocolChart.destroy();
            const protoCtx = document.getElementById('protocolChart').getContext('2d');
            protocolChart = new Chart(protoCtx, {
                type: 'pie',
                data: { labels: Object.keys(data.protocols), datasets: [{ data: Object.values(data.protocols), backgroundColor: ['#4ecdc4', '#ff6b6b', '#ffd966', '#a78bfa'] }] },
                options: { responsive: true, maintainAspectRatio: true, plugins: { legend: { labels: { color: '#eef4ff' } } } }
            });
            if (portChart) portChart.destroy();
            const portCtx = document.getElementById('portChart').getContext('2d');
            const portLabels = Object.keys(data.top_ports);
            const portValues = Object.values(data.top_ports);
            portChart = new Chart(portCtx, {
                type: 'bar',
                data: { labels: portLabels, datasets: [{ label: 'Packets', data: portValues, backgroundColor: '#4ecdc4' }] },
                options: { responsive: true, maintainAspectRatio: true, scales: { y: { beginAtZero: true, ticks: { color: '#eef4ff' } }, x: { ticks: { color: '#eef4ff' } } }, plugins: { legend: { labels: { color: '#eef4ff' } } } }
            });
        } catch(e) { console.error('Traffic stats error', e); }
    }

    async function fetchThreats() {
        try {
            const res = await fetch('/api/threats');
            const threats = await res.json();
            const tbody = document.getElementById('threatsBody');
            if(threats.length === 0) { tbody.innerHTML = '<tr><td colspan="8">No threats detected</td></tr>'; return; }
            tbody.innerHTML = threats.map(t => `
                <tr>
                    <td>${t.time.slice(0,19)}</td>
                    <td>${t.src_ip}</td>
                    <td>${t.country || '-'}</td>
                    <td>${t.protocol || '-'}</td>
                    <td>${t.port || '-'}</td>
                    <td>${t.threat_type || 'ANOMALY'}</td>
                    <td class="${t.risk >= 80 ? 'critical' : (t.risk >= 60 ? 'high' : (t.risk >= 30 ? 'medium' : ''))}">${t.risk}</td>
                    <td>${t.action || '-'}</td>
                </tr>
            `).join('');
        } catch(e) { console.error('Threats error', e); }
    }

    async function fetchBlockedIPs() {
        try {
            const res = await fetch('/api/blocked_ips');
            const blocked = await res.json();
            const tbody = document.getElementById('blockedBody');
            if(blocked.length === 0) { tbody.innerHTML = '<tr><td colspan="4">No IPs blocked</td></tr>'; return; }
            tbody.innerHTML = blocked.map(b => `
                <tr>
                    <td>${b.ip}</td>
                    <td>${b.time.slice(0,19)}</td>
                    <td>${b.reason}</td>
                    <td><button class="danger" onclick="unblockIP('${b.ip}')">Unblock</button></td>
                </tr>
            `).join('');
        } catch(e) { console.error('Blocked IPs error', e); }
    }

    async function fetchGeoIPStatus() {
        if (!geoipAvailable) return;
        try {
            const res = await fetch('/api/geoip_status');
            const data = await res.json();
            document.getElementById('geoipToggle').checked = data.enabled;
        } catch(e) { console.error('GeoIP status error', e); }
    }

    async function blockIP() {
        const ip = document.getElementById('blockIp').value.trim();
        if(!ip) { showAlert('Please enter an IP address', 'error'); return; }
        const reason = document.getElementById('blockReason').value.trim() || 'Manual block from dashboard';
        try {
            const res = await fetch('/api/block', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ip: ip, reason: reason}) });
            const data = await res.json();
            if(data.success) {
                showAlert(`Blocked ${ip} successfully`, 'success');
                document.getElementById('blockIp').value = '';
                document.getElementById('blockReason').value = '';
                fetchBlockedIPs(); fetchStats();
            } else { showAlert(`Failed: ${data.error}`, 'error'); }
        } catch(e) { showAlert('Network error', 'error'); }
    }

    window.unblockIP = async function(ip) {
        if(!confirm(`Unblock ${ip}?`)) return;
        try {
            const res = await fetch('/api/unblock', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ip: ip}) });
            const data = await res.json();
            if(data.success) {
                showAlert(`Unblocked ${ip}`, 'success');
                fetchBlockedIPs(); fetchStats();
            } else { showAlert(`Failed: ${data.error}`, 'error'); }
        } catch(e) { showAlert('Network error', 'error'); }
    };

    document.getElementById('downloadBlockedPdfBtn').addEventListener('click', () => window.location.href = '/api/download_blocked_ips_pdf');
    document.getElementById('downloadAllPdfBtn').addEventListener('click', () => window.location.href = '/api/download_all_ips_pdf');
    document.getElementById('downloadPcapBtn').addEventListener('click', () => window.location.href = '/api/download_pcap');

    if (geoipAvailable) {
        document.getElementById('geoipToggle').addEventListener('change', async (e) => {
            const enabled = e.target.checked;
            try {
                const res = await fetch('/api/geoip_toggle', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({enabled: enabled}) });
                const data = await res.json();
                if(data.success) showAlert(`GeoIP blocking ${enabled ? 'enabled' : 'disabled'}`, 'success');
                else showAlert('Failed to toggle GeoIP', 'error');
            } catch(e) { showAlert('Network error', 'error'); }
        });
    }

    function refreshAll() {
        fetchStats();
        fetchTrafficStats();
        fetchThreats();
        fetchBlockedIPs();
        if (geoipAvailable) fetchGeoIPStatus();
    }
    setInterval(refreshAll, 3000);
    refreshAll();
    document.getElementById('blockBtn').addEventListener('click', blockIP);
</script>
</body>
</html>
'''

# ---------- Flask Routes ----------
@app.route('/')
def dashboard():
    return render_template_string(HTML_TEMPLATE, geoip_available=geoip_available)

@app.route('/api/stats')
def api_stats():
    total_events = db.get_total_event_count()
    conn, cursor = db._get_connection()
    cursor.execute('SELECT DISTINCT src_ip FROM events')
    unique_src = len(cursor.fetchall())
    blocked = db.get_blocked_ips()
    return jsonify({
        'total_events': total_events,
        'unique_src': unique_src,
        'blocked_count': len(blocked)
    })

@app.route('/api/traffic_stats')
def api_traffic_stats():
    events = db.get_recent_events(limit=2000)
    protocol_counter = Counter()
    port_counter = Counter()
    for ev in events:
        proto = ev[4]
        port = ev[5]
        protocol_counter[proto] += 1
        if port:
            port_counter[port] += 1
    top_ports = dict(port_counter.most_common(5))
    return jsonify({
        'protocols': dict(protocol_counter),
        'top_ports': top_ports
    })

@app.route('/api/threats')
def api_threats():
    events = db.get_recent_events(500)
    threats = []
    for e in events:
        if e[7] or e[8] > 0:
            src_ip = e[2]
            country = None
            if geoip and geoip.reader:
                country = geoip.get_country_code(src_ip)
            threats.append({
                'time': e[1],
                'src_ip': src_ip,
                'country': country,
                'protocol': e[4],
                'port': e[5] if e[5] else None,
                'threat_type': e[7] or 'MONITORED',
                'risk': e[8],
                'action': e[9]
            })
    return jsonify(threats[:100])

@app.route('/api/blocked_ips')
def api_blocked_ips():
    blocked = db.get_blocked_ips()
    return jsonify([{'ip': b[0], 'time': b[1], 'reason': b[2]} for b in blocked])

@app.route('/api/block', methods=['POST'])
def api_block():
    data = request.get_json()
    ip = data.get('ip', '').strip()
    reason = data.get('reason', 'Manual block from dashboard')
    if not ip:
        return jsonify({'success': False, 'error': 'IP required'}), 400
    success = block_ip_windows(ip, reason)
    if success:
        db.insert_blocked_ip(ip, reason)
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'error': 'Firewall rule failed'}), 500

@app.route('/api/unblock', methods=['POST'])
def api_unblock():
    data = request.get_json()
    ip = data.get('ip', '').strip()
    if not ip:
        return jsonify({'success': False, 'error': 'IP required'}), 400
    success = unblock_ip_windows(ip)
    if success:
        conn, cursor = db._get_connection()
        cursor.execute('DELETE FROM blocked_ips WHERE ip = ?', (ip,))
        conn.commit()
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'error': 'Unblock failed'}), 500

@app.route('/api/download_blocked_ips_pdf')
def download_blocked_ips_pdf():
    pdf_buffer = generate_blocked_ips_pdf()
    return send_file(pdf_buffer, as_attachment=True, download_name='blocked_ips_log.pdf', mimetype='application/pdf')

@app.route('/api/download_all_ips_pdf')
def download_all_ips_pdf():
    pdf_buffer = generate_all_ips_pdf()
    return send_file(pdf_buffer, as_attachment=True, download_name='all_ip_traffic_log.pdf', mimetype='application/pdf')

@app.route('/api/download_pcap')
def download_pcap():
    if not pcap_sniffer:
        return jsonify({'error': 'PCAP capture not available'}), 500
    packets = pcap_sniffer.get_pcap_buffer()
    if not packets:
        return jsonify({'error': 'No packets captured yet'}), 404
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp:
            wrpcap(tmp.name, packets)
            tmp_path = tmp.name
        with open(tmp_path, 'rb') as f:
            pcap_data = f.read()
        os.unlink(tmp_path)
        return send_file(io.BytesIO(pcap_data), as_attachment=True, download_name='capture.pcap', mimetype='application/vnd.tcpdump.pcap')
    except Exception as e:
        app.logger.error(f"PCAP export failed: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/geoip_status')
def geoip_status():
    import main
    return jsonify({'enabled': getattr(main, 'geoip_enabled', False)})

@app.route('/api/geoip_toggle', methods=['POST'])
def geoip_toggle():
    import main
    data = request.get_json()
    main.geoip_enabled = data.get('enabled', False)
    return jsonify({'success': True})

@app.route('/static/<path:filename>')
def serve_static(filename):
    from flask import send_from_directory
    static_dir = os.path.join(os.path.dirname(__file__), 'static')
    return send_from_directory(static_dir, filename)

# ---------- Startup ----------
def run_dashboard(host='127.0.0.1', port=5000, sniffer=None):
    global db, pcap_sniffer, geoip, geoip_available
    db = Database()
    pcap_sniffer = sniffer
    geoip = GeoIPBlocker()
    geoip_available = geoip.reader is not None
    if not geoip_available:
        print("[Dashboard] GeoIP database not found. Country lookup and blocking disabled.")
    static_folder = os.path.join(os.path.dirname(__file__), 'static')
    os.makedirs(static_folder, exist_ok=True)
    logo_path = os.path.join(static_folder, 'logo.png')
    if not os.path.exists(logo_path):
        print("[Dashboard] No logo.png found in dashboard/static/. Please add your logo for watermark.")
    app.run(host=host, port=port, debug=False, use_reloader=False)