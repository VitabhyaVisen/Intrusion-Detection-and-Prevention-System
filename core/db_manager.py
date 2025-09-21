import sqlite3
import os

DB_FILE = "logs/alerts.db"

def init_db():
    if not os.path.exists("logs"):
        os.mkdir("logs")
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            port INTEGER,
            severity TEXT,
            message TEXT
        )
    ''')
    conn.commit()
    conn.close()

def save_alert(src, dst, protocol, port, severity, message):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        INSERT INTO alerts (src_ip, dst_ip, protocol, port, severity, message)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (src, dst, protocol, port, severity, message))
    conn.commit()
    conn.close()
