"""Flask web UI for the phishing triage pipeline."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from werkzeug.utils import secure_filename

from config import (
    AUTH_ENABLED,
    FLASK_HOST,
    FLASK_PORT,
    FLASK_SECRET_KEY,
    IS_VERCEL,
    MAX_UPLOAD_MB,
    SAMPLE_DIR,
    UPLOAD_DIR,
)
from pipeline import load_report, run_triage
from storage.ioc_db import get_recent_runs
from storage.users_db import bootstrap_admin_from_env, create_user, init_users_db
from web.auth import login_required, registration_allowed, valid_invite_code, verify_credentials

init_users_db()
bootstrap_admin_from_env()

app = Flask(
    __name__,
    template_folder=str(ROOT / "web" / "templates"),
    static_folder=str(ROOT / "public"),
    static_url_path="",
)
app.secret_key = FLASK_SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = IS_VERCEL
app.config["PERMANENT_SESSION_LIFETIME"] = 86400 * 7


@app.route("/login", methods=["GET", "POST"])
def login():
    if not AUTH_ENABLED:
        return redirect(url_for("index"))
    if session.get("logged_in"):
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if verify_credentials(username, password):
            session.permanent = True
            session["logged_in"] = True
            session["username"] = username.strip().lower()
            next_url = request.form.get("next") or request.args.get("next") or url_for("index")
            if not next_url.startswith("/"):
                next_url = url_for("index")
            return redirect(next_url)
        flash("Invalid username or password.", "error")

    return render_template("login.html", next_url=request.args.get("next", ""), registration_allowed=registration_allowed())


@app.route("/register", methods=["GET", "POST"])
def register():
    if not registration_allowed():
        flash("Registration is disabled. Ask your admin for an account.", "error")
        return redirect(url_for("login"))

    if session.get("logged_in"):
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        invite_code = request.form.get("invite_code", "")

        if password != confirm:
            flash("Passwords do not match.", "error")
        elif not valid_invite_code(invite_code):
            flash("Invalid invite code.", "error")
        else:
            ok, message = create_user(username, password=password)
            if ok:
                flash("Account created. You can log in now.", "success")
                return redirect(url_for("login"))
            flash(message, "error")

    return render_template("register.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    sample_exists = (SAMPLE_DIR / "phishing_sample.eml").exists()
    return render_template("index.html", sample_exists=sample_exists)


@app.route("/analyze", methods=["POST"])
@login_required
def analyze():
    skip_intel = request.form.get("skip_intel") == "on"
    simulate_ransomware = request.form.get("simulate_ransomware") == "on"
    raw_text = request.form.get("raw_text", "").strip()
    use_sample = request.form.get("use_sample") == "on"

    email_path = None

    if use_sample:
        email_path = SAMPLE_DIR / "phishing_sample.eml"
        if not email_path.exists():
            flash("Sample email not found.", "error")
            return redirect(url_for("index"))
    elif "email_file" in request.files and request.files["email_file"].filename:
        uploaded = request.files["email_file"]
        filename = secure_filename(uploaded.filename)
        if not filename.lower().endswith(".eml"):
            flash("Please upload a .eml file.", "error")
            return redirect(url_for("index"))
        save_path = UPLOAD_DIR / filename
        uploaded.save(save_path)
        email_path = save_path
    elif raw_text:
        pass
    else:
        flash("Upload an .eml file or paste email content.", "error")
        return redirect(url_for("index"))

    try:
        report = run_triage(
            email_path=email_path,
            raw_text=raw_text if not email_path else None,
            skip_intel=skip_intel,
            simulate_ransomware=simulate_ransomware,
        )
    except Exception as exc:
        flash(f"Analysis failed: {exc}", "error")
        return redirect(url_for("index"))

    return redirect(url_for("results", run_id=report["run_id"]))


@app.route("/results/<run_id>")
@login_required
def results(run_id: str):
    report = load_report(run_id)
    if not report:
        flash("Report not found.", "error")
        return redirect(url_for("index"))
    return render_template("results.html", report=report)


@app.route("/api/analyze", methods=["POST"])
@login_required
def api_analyze():
    """JSON API for programmatic triage."""
    data = request.get_json(silent=True) or {}
    raw_text = data.get("text", "").strip()
    if not raw_text:
        return jsonify({"error": "Provide 'text' in JSON body"}), 400

    report = run_triage(
        raw_text=raw_text,
        skip_intel=data.get("skip_intel", False),
        simulate_ransomware=data.get("simulate_ransomware", False),
    )
    return jsonify(report)


@app.route("/history")
@login_required
def history():
    runs = get_recent_runs(limit=50)
    return render_template("history.html", runs=runs)


@app.context_processor
def inject_auth():
    return {
        "auth_enabled": AUTH_ENABLED,
        "registration_allowed": registration_allowed(),
        "current_user": session.get("username"),
    }


if __name__ == "__main__":
    if IS_VERCEL and not AUTH_ENABLED:
        raise SystemExit("Do not set DISABLE_AUTH on Vercel.")
    if IS_VERCEL and not (WEB_AUTH_USERNAME or registration_allowed()):
        raise SystemExit("Set WEB_AUTH_USERNAME/WEB_AUTH_PASSWORD or enable ALLOW_REGISTRATION on Vercel.")
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=False)
