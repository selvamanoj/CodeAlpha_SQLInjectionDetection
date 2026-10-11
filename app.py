
import os
import re
import sqlite3
from pathlib import Path
from datetime import datetime, timezone

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from dotenv import load_dotenv

load_dotenv()

ROOT = Path(__file__).resolve().parent
DB_PATH = os.getenv("DATABASE_PATH", str(ROOT / "security_monitor.db"))

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "local-demo-secret")

RULES = [
    ("SQL comment marker", re.compile(r"(--|/\*|\*/)")),
    ("SQL statement separator", re.compile(r";")),
    ("Tautology-like expression", re.compile(r"""(?i)\b(or|and)\b\s+['"]?\w+['"]?\s*=\s*['"]?\w+['"]?""")),
    ("UNION SELECT pattern", re.compile(r"\bunion\s+select\b", re.I)),
    ("Dangerous SQL keyword", re.compile(r"\b(drop|alter|truncate|exec|execute)\b", re.I)),
    ("Information schema reference", re.compile(r"\binformation_schema\b", re.I)),
    ("Time-delay function", re.compile(r"\b(sleep|pg_sleep|benchmark)\s*\(", re.I)),
]


def get_db():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with get_db() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                input_value TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                matched_rules TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Detected'
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS demo_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                department TEXT NOT NULL
            )
        """)
        count = connection.execute(
            "SELECT COUNT(*) FROM demo_records"
        ).fetchone()[0]

        if count == 0:
            connection.executemany(
                "INSERT INTO demo_records(full_name,email,department) VALUES(?,?,?)",
                [
                    ("Asha Kumar", "asha@example.com", "AI & Data Science"),
                    ("Ravi Kumar", "ravi@example.com", "Computer Science"),
                    ("Meena Raj", "meena@example.com", "Information Technology"),
                ],
            )


def inspect_input(value):
    matches = [name for name, pattern in RULES if pattern.search(value or "")]
    risk = "High" if len(matches) >= 3 else "Medium" if matches else "Low"
    return risk, matches


def log_event(value, endpoint, risk, matches):
    with get_db() as connection:
        connection.execute(
            """INSERT INTO security_events
            (created_at,source_ip,endpoint,input_value,risk_level,matched_rules)
            VALUES(?,?,?,?,?,?)""",
            (
                datetime.now(timezone.utc).isoformat(timespec="seconds"),
                request.remote_addr or "unknown",
                endpoint,
                (value or "")[:1000],
                risk,
                ", ".join(matches) if matches else "No suspicious rule matched",
            ),
        )


@app.get("/")
def index():
    query = request.args.get("q", "").strip()[:200]
    risk, matches = inspect_input(query)

    if query and matches:
        log_event(query, "/", risk, matches)
        flash("Suspicious input detected and blocked from the search.", "warning")
        rows = []
    else:
        with get_db() as connection:
            if query:
                pattern = f"%{query}%"
                rows = connection.execute(
                    """SELECT * FROM demo_records
                    WHERE full_name LIKE ? OR email LIKE ? OR department LIKE ?
                    ORDER BY id""",
                    (pattern, pattern, pattern),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM demo_records ORDER BY id"
                ).fetchall()

    with get_db() as connection:
        events = connection.execute(
            "SELECT * FROM security_events ORDER BY id DESC LIMIT 10"
        ).fetchall()

    return render_template("index.html", rows=rows, events=events, query=query)


@app.post("/scan")
def scan():
    value = request.form.get("input_value", "")[:1000]
    risk, matches = inspect_input(value)
    log_event(value, "/scan", risk, matches)

    message = f"Scan result: {risk} risk. "
    message += ", ".join(matches) if matches else "No known suspicious pattern detected."
    flash(message, "warning" if matches else "success")

    return redirect(url_for("index"))


@app.post("/events/<int:event_id>/resolve")
def resolve_event(event_id):
    with get_db() as connection:
        connection.execute(
            "UPDATE security_events SET status='Reviewed' WHERE id=?",
            (event_id,),
        )
    flash("Event marked as reviewed.", "success")
    return redirect(url_for("index"))


@app.get("/health")
def health():
    return jsonify(status="ok", service="SQL Injection Detection Demo")


init_db()

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=int(os.getenv("PORT", "5000")),
        debug=False,
    )
