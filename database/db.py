"""
PhishGuard AI — Database Layer
Authors: Sarthak Mehta, Prajwal Kumar, Divyansh Yadav
"""
import sqlite3, os, json
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "phishguard.db")

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    c = conn.cursor()

    c.execute("""CREATE TABLE IF NOT EXISTS scans (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        url          TEXT NOT NULL,
        hostname     TEXT,
        prediction   TEXT NOT NULL,
        label        INTEGER NOT NULL,
        risk_score   REAL NOT NULL,
        prob_safe    REAL,
        prob_susp    REAL,
        prob_phish   REAL,
        ssl_valid    INTEGER DEFAULT 0,
        dns_resolves INTEGER DEFAULT 0,
        http_status  INTEGER,
        domain_age   INTEGER,
        features_json TEXT,
        reasons_json  TEXT,
        ip_address   TEXT,
        scanned_at   DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        username     TEXT UNIQUE NOT NULL,
        password     TEXT NOT NULL,
        role         TEXT DEFAULT 'admin',
        created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_login   DATETIME
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS blacklist (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        url      TEXT UNIQUE NOT NULL,
        reason   TEXT,
        added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        added_by TEXT
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS feedback (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id   INTEGER,
        url       TEXT,
        correct   INTEGER,
        comment   TEXT,
        added_at  DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")

    conn.commit(); conn.close()
    print("[+] DB initialized:", DB_PATH)

def save_scan(url, hostname, prediction, label, risk_score, probs,
              ssl_valid, dns_resolves, http_status, domain_age,
              features, reasons, ip_address):
    conn = get_conn(); c = conn.cursor()
    c.execute("""INSERT INTO scans
        (url,hostname,prediction,label,risk_score,prob_safe,prob_susp,prob_phish,
         ssl_valid,dns_resolves,http_status,domain_age,features_json,reasons_json,ip_address)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (url, hostname, prediction, label, risk_score,
         probs[0], probs[1], probs[2],
         int(ssl_valid), int(dns_resolves), http_status, domain_age,
         json.dumps(features), json.dumps(reasons), ip_address))
    sid = c.lastrowid; conn.commit(); conn.close()
    return sid

def get_recent_scans(limit=50):
    conn = get_conn(); c = conn.cursor()
    c.execute("SELECT * FROM scans ORDER BY scanned_at DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in c.fetchall()]; conn.close(); return rows

def get_stats():
    conn = get_conn(); c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM scans"); total = c.fetchone()[0]
    c.execute("SELECT label, COUNT(*) FROM scans GROUP BY label")
    by_label = {r[0]: r[1] for r in c.fetchall()}
    c.execute("""SELECT DATE(scanned_at) d, COUNT(*) n FROM scans
                 WHERE scanned_at >= DATE('now','-7 days')
                 GROUP BY DATE(scanned_at) ORDER BY d""")
    daily = [{"day": r[0], "count": r[1]} for r in c.fetchall()]
    c.execute("SELECT AVG(risk_score) FROM scans"); avg_risk = c.fetchone()[0] or 0
    c.execute("SELECT COUNT(*) FROM scans WHERE label=2 AND scanned_at >= DATE('now','-1 day')"); threats_today = c.fetchone()[0]
    c.execute("SELECT url, risk_score, scanned_at FROM scans WHERE label=2 ORDER BY risk_score DESC LIMIT 5")
    top_threats = [dict(r) for r in c.fetchall()]
    conn.close()
    return {"total": total, "by_label": by_label, "daily": daily,
            "avg_risk": round(avg_risk,1), "threats_today": threats_today, "top_threats": top_threats}

def get_user(username):
    conn = get_conn(); c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    r = c.fetchone(); conn.close()
    return dict(r) if r else None

def create_user(username, hashed_pw, role="admin"):
    conn = get_conn(); c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username,password,role) VALUES (?,?,?)",
                  (username, hashed_pw, role))
        conn.commit(); uid = c.lastrowid
    except sqlite3.IntegrityError: uid = None
    finally: conn.close()
    return uid

def update_last_login(uid):
    conn = get_conn(); c = conn.cursor()
    c.execute("UPDATE users SET last_login=? WHERE id=?", (datetime.now(), uid))
    conn.commit(); conn.close()

def add_blacklist(url, reason, added_by=None):
    conn = get_conn(); c = conn.cursor()
    try:
        c.execute("INSERT INTO blacklist (url,reason,added_by) VALUES (?,?,?)",
                  (url, reason, added_by)); conn.commit(); ok = True
    except sqlite3.IntegrityError: ok = False
    finally: conn.close()
    return ok

def is_blacklisted(url):
    conn = get_conn(); c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM blacklist WHERE url=?", (url,))
    n = c.fetchone()[0]; conn.close(); return n > 0

def get_blacklist(limit=100):
    conn = get_conn(); c = conn.cursor()
    c.execute("SELECT * FROM blacklist ORDER BY added_at DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in c.fetchall()]; conn.close(); return rows

def add_feedback(scan_id, url, correct, comment):
    conn = get_conn(); c = conn.cursor()
    c.execute("INSERT INTO feedback (scan_id,url,correct,comment) VALUES (?,?,?,?)",
              (scan_id, url, int(correct), comment))
    conn.commit(); conn.close()
