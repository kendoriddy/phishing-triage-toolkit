import sqlite3
from datetime import datetime

from werkzeug.security import check_password_hash, generate_password_hash

from config import (
    DB_PATH,
    WEB_AUTH_PASSWORD,
    WEB_AUTH_PASSWORD_HASH,
    WEB_AUTH_USERNAME,
)


def init_users_db(db_path=None) -> None:
    path = db_path or DB_PATH
    with sqlite3.connect(path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.commit()


def bootstrap_admin_from_env(db_path=None) -> None:
    """Create the admin user from env vars if no users exist yet."""
    if not WEB_AUTH_USERNAME or not (WEB_AUTH_PASSWORD or WEB_AUTH_PASSWORD_HASH):
        return

    path = db_path or DB_PATH
    init_users_db(path)

    if user_count(path) > 0:
        return

    if WEB_AUTH_PASSWORD_HASH:
        password_hash = WEB_AUTH_PASSWORD_HASH
    else:
        password_hash = generate_password_hash(WEB_AUTH_PASSWORD)

    create_user(WEB_AUTH_USERNAME, password_hash=password_hash, is_admin=True, db_path=path)


def user_count(db_path=None) -> int:
    path = db_path or DB_PATH
    init_users_db(path)
    with sqlite3.connect(path) as conn:
        row = conn.execute("SELECT COUNT(*) FROM users").fetchone()
    return row[0] if row else 0


def get_user(username: str, db_path=None) -> dict | None:
    path = db_path or DB_PATH
    init_users_db(path)
    with sqlite3.connect(path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT id, username, password_hash, is_admin, created_at FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    return dict(row) if row else None


def create_user(
    username: str,
    password: str | None = None,
    password_hash: str | None = None,
    is_admin: bool = False,
    db_path=None,
) -> tuple[bool, str]:
    path = db_path or DB_PATH
    init_users_db(path)

    username = username.strip().lower()
    if len(username) < 3:
        return False, "Username must be at least 3 characters."
    if not password and not password_hash:
        return False, "Password is required."
    if password and len(password) < 8:
        return False, "Password must be at least 8 characters."

    hashed = password_hash or generate_password_hash(password)

    try:
        with sqlite3.connect(path) as conn:
            conn.execute(
                """
                INSERT INTO users (username, password_hash, is_admin, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (username, hashed, int(is_admin), datetime.now().isoformat()),
            )
            conn.commit()
    except sqlite3.IntegrityError:
        return False, "Username already taken."

    return True, "Account created."


def verify_user_password(username: str, password: str, db_path=None) -> bool:
    user = get_user(username.strip().lower(), db_path=db_path)
    if not user:
        return False
    return check_password_hash(user["password_hash"], password)
