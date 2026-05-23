import sqlite3
from datetime import datetime

from config import DB_PATH


def init_db(db_path=None) -> None:
    """Create IOC history tables if they do not exist."""
    path = db_path or DB_PATH
    with sqlite3.connect(path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS triage_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                sender TEXT,
                subject TEXT,
                risk_score INTEGER,
                verdict TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ioc_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER,
                ioc_type TEXT NOT NULL,
                ioc_value TEXT NOT NULL,
                FOREIGN KEY (run_id) REFERENCES triage_runs(id)
            )
            """
        )
        conn.commit()


def save_triage_run(email_data: dict, iocs: dict, score: int, verdict: str, db_path=None) -> int:
    """Persist a triage run and its IOCs to SQLite."""
    path = db_path or DB_PATH
    init_db(path)

    with sqlite3.connect(path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO triage_runs (timestamp, sender, subject, risk_score, verdict)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                datetime.now().isoformat(),
                email_data.get("from"),
                email_data.get("subject"),
                score,
                verdict,
            ),
        )
        run_id = cursor.lastrowid

        for ioc_type, values in iocs.items():
            for value in values:
                conn.execute(
                    "INSERT INTO ioc_history (run_id, ioc_type, ioc_value) VALUES (?, ?, ?)",
                    (run_id, ioc_type, value),
                )

        conn.commit()
        return run_id


def get_recent_runs(limit: int = 10, db_path=None) -> list[dict]:
    """Fetch recent triage runs from history."""
    path = db_path or DB_PATH
    init_db(path)

    with sqlite3.connect(path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT id, timestamp, sender, subject, risk_score, verdict
            FROM triage_runs
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [dict(row) for row in rows]
