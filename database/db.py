import sqlite3
import threading
from datetime import datetime
import os
from config import DB_PATH

class Database:
    _local = threading.local()

    def __init__(self):
        self._ensure_db_dir()
        self._get_connection()  # create tables for the calling thread

    def _ensure_db_dir(self):
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

    def _get_connection(self):
        if not hasattr(self._local, 'conn'):
            self._local.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
            self._local.cursor = self._local.conn.cursor()
            self._create_tables(self._local.cursor)
        return self._local.conn, self._local.cursor

    def _create_tables(self, cursor):
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                protocol TEXT,
                port INTEGER,
                packet_size INTEGER,
                threat_type TEXT,
                risk_score INTEGER,
                action TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                src_ip TEXT,
                threat_type TEXT,
                risk_score INTEGER,
                details TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE,
                block_time TEXT,
                reason TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                report_path TEXT,
                type TEXT
            )
        ''')
        self._local.conn.commit()

    def insert_event(self, src_ip, dst_ip, protocol, port, pkt_size, threat_type, risk_score, action):
        conn, cursor = self._get_connection()
        ts = datetime.now().isoformat()
        cursor.execute('''
            INSERT INTO events (timestamp, src_ip, dst_ip, protocol, port, packet_size, threat_type, risk_score, action)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (ts, src_ip, dst_ip, protocol, port, pkt_size, threat_type, risk_score, action))
        conn.commit()

    def insert_threat(self, src_ip, threat_type, risk_score, details=""):
        conn, cursor = self._get_connection()
        ts = datetime.now().isoformat()
        cursor.execute('''
            INSERT INTO threats (timestamp, src_ip, threat_type, risk_score, details)
            VALUES (?, ?, ?, ?, ?)
        ''', (ts, src_ip, threat_type, risk_score, details))
        conn.commit()

    def insert_blocked_ip(self, ip, reason):
        conn, cursor = self._get_connection()
        ts = datetime.now().isoformat()
        try:
            cursor.execute('''
                INSERT INTO blocked_ips (ip, block_time, reason)
                VALUES (?, ?, ?)
            ''', (ip, ts, reason))
            conn.commit()
        except sqlite3.IntegrityError:
            pass

    def get_recent_events(self, limit=100):
        _, cursor = self._get_connection()
        cursor.execute('SELECT * FROM events ORDER BY timestamp DESC LIMIT ?', (limit,))
        return cursor.fetchall()

    def get_threat_summary(self, hours=24):
        _, cursor = self._get_connection()
        cursor.execute('''
            SELECT threat_type, COUNT(*), AVG(risk_score) FROM threats
            WHERE timestamp > datetime('now', '-' || ? || ' hours')
            GROUP BY threat_type
        ''', (hours,))
        return cursor.fetchall()

    def get_blocked_ips(self):
        _, cursor = self._get_connection()
        cursor.execute('SELECT ip, block_time, reason FROM blocked_ips ORDER BY block_time DESC')
        return cursor.fetchall()

    def get_total_event_count(self):
        _, cursor = self._get_connection()
        cursor.execute('SELECT COUNT(*) FROM events')
        return cursor.fetchone()[0]

    def close(self):
        if hasattr(self._local, 'conn'):
            self._local.conn.close()
            del self._local.conn
            del self._local.cursor