"""Web UI authentication."""

import functools
import secrets

from flask import flash, redirect, request, session, url_for
from werkzeug.security import check_password_hash

from config import (
    AUTH_ENABLED,
    REGISTRATION_ENABLED,
    REGISTRATION_INVITE_CODE,
    WEB_API_KEY,
    WEB_AUTH_PASSWORD,
    WEB_AUTH_PASSWORD_HASH,
    WEB_AUTH_USERNAME,
)
from storage.users_db import verify_user_password


def login_required(view):
    """Require a logged-in session (or valid API key for JSON routes)."""

    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if not AUTH_ENABLED:
            return view(*args, **kwargs)
        if session.get("logged_in"):
            return view(*args, **kwargs)
        if _valid_api_key():
            return view(*args, **kwargs)
        if request.path.startswith("/api/"):
            from flask import jsonify

            return jsonify({"error": "Unauthorized"}), 401
        flash("Please log in to continue.", "error")
        return redirect(url_for("login", next=request.path))

    return wrapped


def verify_credentials(username: str, password: str) -> bool:
    if not AUTH_ENABLED:
        return True

    if verify_user_password(username, password):
        return True

    # Fallback: env-based admin (before bootstrap or legacy config)
    env_user = WEB_AUTH_USERNAME.strip().lower()
    if not env_user or username.strip().lower() != env_user:
        return False
    if WEB_AUTH_PASSWORD_HASH:
        return check_password_hash(WEB_AUTH_PASSWORD_HASH, password)
    if WEB_AUTH_PASSWORD:
        return secrets.compare_digest(password, WEB_AUTH_PASSWORD)
    return False


def registration_allowed() -> bool:
    return AUTH_ENABLED and REGISTRATION_ENABLED


def valid_invite_code(code: str) -> bool:
    if not REGISTRATION_INVITE_CODE:
        return False
    return secrets.compare_digest(code.strip(), REGISTRATION_INVITE_CODE)


def _valid_api_key() -> bool:
    if not WEB_API_KEY:
        return False
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.removeprefix("Bearer ").strip()
    return bool(token) and secrets.compare_digest(token, WEB_API_KEY)
