"""
PhishGuard AI — Advanced Phishing Detection System
Real ML + Real Live Checks (DNS, SSL, WHOIS, HTTP)
Authors: Sarthak Mehta, Prajwal Kumar, Divyansh Yadav
"""

import os, pickle, json, threading, logging, secrets, ipaddress
from dotenv import load_dotenv
load_dotenv()
from concurrent.futures import ThreadPoolExecutor, as_completed
import numpy as np
from flask import (Flask, render_template, request, jsonify,
                   redirect, url_for, session, flash)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta, timezone

from utils.analyzer import full_analysis, get_recommendations, FEATURE_COLS
from utils.analyzer import _public_ips as _analyzer_public_ips
from database.db import (init_db, save_scan, get_recent_scans, get_stats,
                         get_user, get_user_by_email, get_user_by_id, get_all_users,
                         create_user, update_last_login,
                         create_otp_challenge, get_otp_challenge,
                         increment_otp_attempts, delete_otp_challenge,
                         get_user_scans, get_user_stats,
                         add_blacklist, is_blacklisted, get_blacklist, add_feedback)

# ── App ───────────────────────────────────────────────────────
app = Flask(__name__)
secret_key = os.environ.get("SECRET_KEY")
if not secret_key:
    raise RuntimeError("SECRET_KEY environment variable is required.")
app.secret_key = secret_key
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("SESSION_COOKIE_SECURE", "1").lower() in {"1", "true", "yes"}
app.config["MAX_CONTENT_LENGTH"] = 256 * 1024

csrf = CSRFProtect(app)
limiter = Limiter(key_func=get_remote_address, app=app, default_limits=[])
logger = logging.getLogger(__name__)

BASE      = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE, "models", "phishguard_model.pkl")
META_PATH  = os.path.join(BASE, "models", "model_metadata.json")

LABEL_MAP   = {0: "Safe", 1: "Suspicious", 2: "Phishing"}
LABEL_CLASS = {0: "safe", 1: "suspicious", 2: "phishing"}


def _public_ips(hostname):
    return _analyzer_public_ips(hostname)


def is_public_scan_target(hostname):
    """Return whether a hostname resolves only to globally routable addresses."""
    try:
        direct = ipaddress.ip_address(hostname)
        if not direct.is_global:
            return False, "Private or non-public IP addresses are not scannable."
        return True, None
    except ValueError:
        pass

    ips = _public_ips(hostname)
    if not ips:
        return False, "Host could not be resolved to a public address."
    if any(not ipaddress.ip_address(ip).is_global for ip in ips):
        return False, "Host resolves to a private or non-public address."
    return True, None


# ── Load Model ────────────────────────────────────────────────
model    = None
metadata = {}
try:
    with open(MODEL_PATH, "rb") as f: model = pickle.load(f)
    with open(META_PATH)        as f: metadata = json.load(f)
    print(f"[+] Model loaded | Accuracy: {metadata.get('accuracy',0)*100:.1f}%")
except FileNotFoundError:
    print("[!] Model not found — run dataset/download_real_dataset.py, then train_model.py")

# ── Auth Decorator ────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Login required.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get("role") != "admin":
            return jsonify({"error": "Admin access required."}), 403
        return f(*args, **kwargs)
    return wrapper

# ── Startup ───────────────────────────────────────────────────
def setup():
    init_db()
    admin_username = os.environ.get("ADMIN_USERNAME")
    admin_password = os.environ.get("ADMIN_PASSWORD")
    if admin_username and admin_password and not get_user(admin_username):
        create_user(admin_username, generate_password_hash(admin_password), "admin")
        print(f"[+] Bootstrap admin created: {admin_username}")
    elif not admin_username or not admin_password:
        logger.warning("ADMIN_USERNAME/ADMIN_PASSWORD not set; no admin account will be bootstrapped.")

# Initialize the database for both local execution and WSGI servers.
setup()

# ─────────────────────────────────────────────────────────────
#  PUBLIC ROUTES
# ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    if "user_id" not in session:
        return redirect(url_for("user_login"))
    model_ok = model is not None
    return render_template("index.html", model_ok=model_ok, metadata=metadata)


@app.route("/scan", methods=["POST"])
@limiter.limit("20/minute")
@csrf.exempt
def scan():
    if not model:
        return jsonify({"error": "Model not loaded. Run python train_model.py first."}), 503

    data = request.get_json()
    url  = (data or {}).get("url", "").strip()

    if not url:
        return jsonify({"error": "No URL provided."}), 400
    if len(url) > 2048:
        return jsonify({"error": "URL too long."}), 400

    # Normalize
    if not url.startswith(("http://","https://")):
        url = "https://" + url

    # ── Full real analysis ────────────────────────────────────
    analysis = full_analysis(url)
    features = analysis["features"]
    vec      = np.array(analysis["feature_vector"]).reshape(1, -1)

    # ── ML Prediction ─────────────────────────────────────────
    label    = int(model.predict(vec)[0])
    probs    = model.predict_proba(vec)[0]

    # Blacklist override
    if is_blacklisted(url):
        label  = 2
        probs  = np.array([0.0, 0.02, 0.98])

    # Risk score (weighted combo)
    risk_score = round(min(probs[1] * 45 + probs[2] * 100, 99.9), 1)

    prediction   = LABEL_MAP[label]
    pred_class   = LABEL_CLASS[label]
    reasons      = analysis["reasons"]
    recommendations = get_recommendations(label, analysis)

    # ── Save to DB ────────────────────────────────────────────
    ssl_valid    = analysis["ssl"].get("valid", False)
    dns_resolves = analysis["dns"].get("resolves", False)
    http_status  = analysis["http"].get("status_code")
    domain_age   = analysis["whois"].get("age_days")

    scan_id = save_scan(
        url       = url,
        hostname  = analysis["hostname"],
        prediction= prediction,
        label     = label,
        risk_score= risk_score,
        probs     = [round(float(p),4) for p in probs],
        ssl_valid = ssl_valid,
        dns_resolves = dns_resolves,
        http_status  = http_status,
        domain_age   = domain_age,
        features     = features,
        reasons      = reasons,
        ip_address   = request.remote_addr,
        user_id      = session.get("user_id"),
    )

    return jsonify({
        "scan_id":        scan_id,
        "url":            url,
        "hostname":       analysis["hostname"],
        "prediction":     prediction,
        "prediction_class": pred_class,
        "risk_score":     risk_score,
        "label":          label,
        "probabilities": {
            "safe":       round(float(probs[0]) * 100, 1),
            "suspicious": round(float(probs[1]) * 100, 1),
            "phishing":   round(float(probs[2]) * 100, 1),
        },
        "features":       features,
        "ssl":            analysis["ssl"],
        "dns":            analysis["dns"],
        "http":           analysis["http"],
        "whois":          analysis["whois"],
        "gsb":            analysis["gsb"],
        "reasons":        reasons,
        "recommendations": recommendations,
        "scanned_at":     analysis["scanned_at"],
    })


@app.route("/api/bulk-scan", methods=["POST"])
@limiter.limit("5/minute")
@csrf.exempt
def bulk_scan():
    """Scan multiple URLs at once (up to 10)."""
    if not model:
        return jsonify({"error": "Model not loaded."}), 503
    data = request.get_json()
    urls = (data or {}).get("urls", [])
    if not isinstance(urls, list) or len(urls) > 10:
        return jsonify({"error": "Provide between 1 and 10 URLs."}), 400
    if not all(isinstance(u, str) for u in urls):
        return jsonify({"error": "Each URL must be a string."}), 400
    if not urls:
        return jsonify({"error": "No URLs provided."}), 400

    normalized = []
    seen = set()
    for raw_url in urls:
        url = raw_url.strip()
        if not url:
            continue
        if len(url) > 2048:
            continue
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        if url not in seen:
            normalized.append(url)
            seen.add(url)

    if not normalized:
        return jsonify({"error": "No valid URLs provided."}), 400

    def worker(url):
        analysis = full_analysis(url)
        vec = np.array(analysis["feature_vector"]).reshape(1, -1)
        label = int(model.predict(vec)[0])
        probs = model.predict_proba(vec)[0]
        if is_blacklisted(url):
            label, probs = 2, np.array([0.0, 0.02, 0.98])
        risk = round(min(probs[1] * 45 + probs[2] * 100, 99.9), 1)
        return {
            "url": url,
            "prediction": LABEL_MAP[label],
            "prediction_class": LABEL_CLASS[label],
            "risk_score": risk,
        }

    results = []
    with ThreadPoolExecutor(max_workers=min(4, len(normalized))) as pool:
        futures = {pool.submit(worker, u): u for u in normalized}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception:
                results.append({"url": futures[future], "error": "Scan failed"})
    return jsonify({"results": results})


@app.route("/api/features/<path:url>")
@limiter.limit("20/minute")
def explain_features(url):
    """Return feature explanation for a URL."""
    if not url.startswith(("http://","https://")): url = "https://" + url
    from utils.analyzer import extract_30_features
    feats = extract_30_features(url)
    fi    = metadata.get("feature_importance", {})
    explained = [
        {"feature": k, "value": feats[k], "importance": fi.get(k, 0)}
        for k in FEATURE_COLS
    ]
    explained.sort(key=lambda x: x["importance"], reverse=True)
    return jsonify({"url": url, "features": explained})


@app.route("/api/history")
@login_required
def api_history():
    return jsonify(get_recent_scans(25))


@app.route("/api/feedback", methods=["POST"])
@limiter.limit("20/minute")
@csrf.exempt
def api_feedback():
    d = request.get_json(silent=True) or {}
    if not isinstance(d.get("correct", True), bool):
        return jsonify({"error": "correct must be boolean."}), 400
    if d.get("comment", "") and len(str(d["comment"])) > 1000:
        return jsonify({"error": "Comment too long."}), 400
    add_feedback(d.get("scan_id"), d.get("url"), d.get("correct", True), str(d.get("comment", "")))
    return jsonify({"ok": True})


# ─────────────────────────────────────────────────────────────
#  AUTH
# ─────────────────────────────────────────────────────────────

@app.route("/admin-login", methods=["GET", "POST"])
def admin_login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        u = request.form.get("username","").strip()
        p = request.form.get("password","")
        if not u or not p:
            flash("Enter username and password.", "error"); return render_template("admin_login.html")
        user = get_user(u)
        if user and check_password_hash(user["password"], p):
            session.clear()
            session["user_id"]  = user["id"]
            session["username"] = user["username"]
            session["role"]     = user["role"]
            update_last_login(user["id"])
            flash(f"Welcome back, {u}!", "success")
            if user["role"] != "admin":
                flash("Use the user login portal for this account.", "warning")
                return redirect(url_for("user_login"))
            return redirect(url_for("dashboard"))
        flash("Invalid credentials.", "error")
    return render_template("admin_login.html")

@app.route("/login")
def login():
    return redirect(url_for("user_login"))

@app.route("/user-login", methods=["GET", "POST"])
def user_login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = get_user_by_email(email)
        if not user or user["role"] != "user" or not check_password_hash(user["password"], password):
            flash("Invalid email or password.", "error")
            return render_template("user_login.html")
        otp = f"{secrets.randbelow(1000000):06d}"
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
        create_otp_challenge(user["id"], generate_password_hash(otp), expires_at.isoformat())
        session["pending_user_id"] = user["id"]
        session["development_otp"] = otp
        return redirect(url_for("verify_otp"))
    return render_template("user_login.html")

@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    user_id = session.get("pending_user_id")
    if not user_id:
        return redirect(url_for("user_login"))
    challenge = get_otp_challenge(user_id)
    if request.method == "POST":
        otp = request.form.get("otp", "").strip()
        expired = not challenge or challenge["attempts"] >= 5
        if challenge and not expired:
            expires_at = datetime.fromisoformat(challenge["expires_at"]).astimezone(timezone.utc)
            expired = expires_at < datetime.now(timezone.utc)
        if expired:
            if challenge:
                delete_otp_challenge(challenge["id"])
            session.pop("pending_user_id", None)
            session.pop("development_otp", None)
            flash("Verification expired. Please log in again.", "error")
            return redirect(url_for("user_login"))
        increment_otp_attempts(challenge["id"])
        if check_password_hash(challenge["otp_hash"], otp):
            user = get_user_by_id(user_id)
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = "user"
            update_last_login(user["id"])
            delete_otp_challenge(challenge["id"])
            return redirect(url_for("index"))
        flash("Incorrect verification code.", "error")
    return render_template("verify_otp.html", development_otp=session.get("development_otp"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirmation = request.form.get("confirm_password", "")
        valid_username = 3 <= len(username) <= 30 and username.replace("_", "").isalnum()
        valid_email = "@" in email and "." in email.rsplit("@", 1)[-1]
        if not valid_username:
            flash("Username must be 3–30 characters using letters, numbers, or underscores.", "error")
        elif not valid_email:
            flash("Enter a valid email address.", "error")
        elif len(password) < 8:
            flash("Password must contain at least 8 characters.", "error")
        elif password != confirmation:
            flash("Passwords do not match.", "error")
        elif create_user(username, generate_password_hash(password), "user", email) is None:
            flash("Username or email is already registered.", "error")
        else:
            flash("Account created. You can now sign in.", "success")
            return redirect(url_for("user_login"))
    return render_template("register.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("index"))


# ─────────────────────────────────────────────────────────────
#  ADMIN
# ─────────────────────────────────────────────────────────────

@app.route("/dashboard")
@login_required
@admin_required
def dashboard():
    if session.get("role") != "admin":
        return redirect(url_for("user_dashboard"))
    stats   = get_stats()
    scans   = get_recent_scans(20)
    bl      = get_blacklist(15)
    users   = get_all_users()
    return render_template("dashboard.html",
        stats=stats, scans=scans, blacklist=bl, users=users,
        username=session.get("username"), metadata=metadata)

@app.route("/user-dashboard")
@login_required
def user_dashboard():
    if session.get("role") == "admin":
        return redirect(url_for("dashboard"))
    stats = get_user_stats(session["user_id"])
    scans = get_user_scans(session["user_id"], 50)
    return render_template("user_dashboard.html", stats=stats, scans=scans,
                           username=session.get("username"))


@app.route("/admin/blacklist/add", methods=["POST"])
@limiter.limit("20/minute")
@login_required
@admin_required
def admin_blacklist_add():
    u = request.form.get("url","").strip()
    r = request.form.get("reason","Manually blacklisted").strip()
    if len(u) > 2048 or len(r) > 500:
        flash("Input is too long.", "error")
        return redirect(url_for("dashboard"))
    if u:
        ok = add_blacklist(u, r, session.get("username"))
        flash(f"'{u}' added." if ok else "Already blacklisted.", "success" if ok else "warning")
    return redirect(url_for("dashboard"))


@app.route("/api/stats")
@login_required
@admin_required
def api_stats():
    return jsonify(get_stats())


@app.route("/healthz")
def healthz():
    return jsonify({"status": "ok", "model_loaded": model is not None, "version": metadata.get("model_version", "unknown")})

@app.route("/api/model-info")
def api_model_info():
    return jsonify(metadata)


@app.after_request
def security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    return response

@app.errorhandler(404)
def e404(e): return render_template("404.html"), 404

@app.errorhandler(429)
def e429(e): return jsonify({"error": "Too many requests. Please try again later."}), 429

@app.errorhandler(500)
def e500(e):
    logger.exception("Unhandled server error")
    return jsonify({"error": "Server error"}), 500


if __name__ == "__main__":
    setup()
    port = int(os.environ.get("PORT", "5000"))
    debug = os.environ.get("FLASK_DEBUG", "0").lower() in {"1", "true", "yes"}
    app.run(debug=debug, host="0.0.0.0", port=port)
