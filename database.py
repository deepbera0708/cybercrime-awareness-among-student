import random
import sqlite3
from datetime import date, timedelta

from flask import g, current_app
from werkzeug.security import generate_password_hash

REGIONS = [
    "North America",
    "South America",
    "Europe",
    "Middle East",
    "Africa",
    "Asia Pacific",
    "South Asia",
]

THREAT_TYPES = [
    "Phishing",
    "Ransomware",
    "Malware",
    "DDoS",
    "Data Breach",
    "Identity Theft",
    "Insider Threat",
    "Supply Chain Attack",
]

SEVERITIES = ["Low", "Medium", "High", "Critical"]

COUNTRIES_BY_REGION = {
    "North America": ["United States", "Canada", "Mexico"],
    "South America": ["Brazil", "Argentina", "Chile", "Colombia"],
    "Europe": ["Germany", "France", "United Kingdom", "Poland", "Italy"],
    "Middle East": ["UAE", "Saudi Arabia", "Israel", "Turkey"],
    "Africa": ["Nigeria", "South Africa", "Kenya", "Egypt"],
    "Asia Pacific": ["Japan", "Australia", "South Korea", "Singapore"],
    "South Asia": ["India", "Pakistan", "Bangladesh", "Sri Lanka"],
}

SOURCES = ["Internal SOC", "OSINT Feed", "Partner Report", "Honeypot Network", "Threat Intel Vendor"]

DESCRIPTIONS = {
    "Phishing": "Targeted phishing campaign detected against employee mailboxes.",
    "Ransomware": "Ransomware encryption activity detected on endpoint(s).",
    "Malware": "Malicious payload identified during routine scan.",
    "DDoS": "Distributed denial-of-service traffic spike observed.",
    "Data Breach": "Unauthorized access to sensitive data repository.",
    "Identity Theft": "Credential stuffing / account takeover attempts logged.",
    "Insider Threat": "Anomalous internal access pattern flagged by UEBA.",
    "Supply Chain Attack": "Compromised third-party dependency detected.",
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    active_flag INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS threat_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    region TEXT NOT NULL,
    country TEXT NOT NULL,
    threat_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    incident_count INTEGER NOT NULL DEFAULT 1,
    event_date TEXT NOT NULL,
    source TEXT,
    description TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_date ON threat_events(event_date);
CREATE INDEX IF NOT EXISTS idx_events_region ON threat_events(region);
CREATE INDEX IF NOT EXISTS idx_events_type ON threat_events(threat_type);
CREATE INDEX IF NOT EXISTS idx_events_severity ON threat_events(severity);
"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_app(app):
    app.teardown_appcontext(close_db)


def _seed_users(db):
    demo_users = [
        ("admin", "admin@ccad.local", "Admin@123", "admin"),
        ("analyst1", "analyst1@ccad.local", "Analyst@123", "analyst"),
        ("user1", "user1@ccad.local", "User@123", "user"),
    ]
    created = []
    for username, email, pwd, role in demo_users:
        existing = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if existing:
            continue
        db.execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
            (username, email, generate_password_hash(pwd), role),
        )
        created.append(username)
    db.commit()
    return created


def _seed_threat_events(db, days=365, min_per_day=8, max_per_day=25):
    existing = db.execute("SELECT id FROM threat_events LIMIT 1").fetchone()
    if existing:
        return 0

    today = date.today()
    rows = []
    for day_offset in range(days, -1, -1):
        current_day = today - timedelta(days=day_offset)
        num_events = random.randint(min_per_day, max_per_day)
        for _ in range(num_events):
            region = random.choice(REGIONS)
            country = random.choice(COUNTRIES_BY_REGION[region])
            threat_type = random.choices(
                THREAT_TYPES, weights=[18, 16, 15, 12, 10, 12, 8, 9], k=1
            )[0]
            severity = random.choices(SEVERITIES, weights=[0.35, 0.35, 0.20, 0.10], k=1)[0]
            incident_count = random.randint(1, 40)
            if severity == "Critical":
                incident_count = random.randint(10, 80)

            rows.append((
                region, country, threat_type, severity, incident_count,
                current_day.isoformat(), random.choice(SOURCES),
                DESCRIPTIONS.get(threat_type, "Suspicious activity detected."),
            ))

    db.executemany(
        """INSERT INTO threat_events
           (region, country, threat_type, severity, incident_count, event_date, source, description)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        rows,
    )
    db.commit()
    return len(rows)


def init_db(app, reseed=False):
    """Create tables (if needed) and seed demo users + mock events (if empty)."""
    with app.app_context():
        db = get_db()
        db.executescript(SCHEMA)
        db.commit()
        created_users = _seed_users(db)
        created_events = _seed_threat_events(db)
        return created_users, created_events
