"""
PhishGuard AI — Advanced Phishing Detection System
Real ML + Real Live Checks (DNS, SSL, WHOIS, HTTP)
Authors: Sarthak Mehta, Prajwal Kumar, Divyansh Yadav
"""

import os, pickle, json, threading
import numpy as np
from flask import (Flask, render_template, request, jsonify,
                   redirect, url_for, session, flash)
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime

from utils.analyzer import full_analysis, get_recommendations, FEATURE_COLS
from database.db import (init_db, save_scan, get_recent_scans, get_stats,
                         get_user, create_user, update_last_login,
                         add_blacklist, is_blacklisted, get_blacklist, add_feedback)

# ── App ───────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "phishguard-secret-2024-sliet")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"]  = "Lax"

BASE      = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE, "models", "phishguard_model.pkl")
META_PATH  = os.path.join(BASE, "models", "model_metadata.json")

LABEL_MAP   = {0: "Safe", 1: "Suspicious", 2: "Phishing"}
LABEL_CLASS = {0: "safe", 1: "suspicious", 2: "phishing"}

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

# ── Startup ───────────────────────────────────────────────────
def setup():
    init_db()
    if not get_user("admin"):
        create_user("admin", generate_password_hash("admin@123"), "admin")
        print("[+] Default admin: admin / admin@123")

# ─────────────────────────────────────────────────────────────
#  PUBLIC ROUTES
# ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    model_ok = model is not None
    return render_template("index.html", model_ok=model_ok, metadata=metadata)


@app.route("/scan", methods=["POST"])
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
def bulk_scan():
    """Scan multiple URLs at once (up to 10)."""
    if not model:
        return jsonify({"error": "Model not loaded."}), 503
    data = request.get_json()
    urls = (data or {}).get("urls", [])[:10]
    if not urls:
        return jsonify({"error": "No URLs provided."}), 400

    results = []
    for url in urls:
        url = url.strip()
        if not url: continue
        if not url.startswith(("http://","https://")): url = "https://" + url
        analysis = full_analysis(url)
        vec   = np.array(analysis["feature_vector"]).reshape(1, -1)
        label = int(model.predict(vec)[0])
        probs = model.predict_proba(vec)[0]
        if is_blacklisted(url): label = 2; probs = np.array([0.0, 0.02, 0.98])
        risk  = round(min(probs[1]*45 + probs[2]*100, 99.9), 1)
        results.append({
            "url": url, "prediction": LABEL_MAP[label],
            "prediction_class": LABEL_CLASS[label],
            "risk_score": risk,
        })
    return jsonify({"results": results})


@app.route("/api/features/<path:url>")
def explain_features(url):
    """Return feature explanation for a URL."""
    if not url.startswith(("http://","https://")): url = "https://" + url
    from utils.analyzer import extract_30_features, FEATURE_COLS
    feats = extract_30_features(url)
    fi    = metadata.get("feature_importance", {})
    explained = [
        {"feature": k, "value": feats[k], "importance": fi.get(k, 0)}
        for k in FEATURE_COLS
    ]
    explained.sort(key=lambda x: x["importance"], reverse=True)
    return jsonify({"url": url, "features": explained})


@app.route("/api/history")
def api_history():
    return jsonify(get_recent_scans(10))


@app.route("/api/feedback", methods=["POST"])
def api_feedback():
    d = request.get_json()
    add_feedback(d.get("scan_id"), d.get("url"), d.get("correct", True), d.get("comment",""))
    return jsonify({"ok": True})


# ─────────────────────────────────────────────────────────────
#  AUTH
# ─────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET","POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        u = request.form.get("username","").strip()
        p = request.form.get("password","")
        if not u or not p:
            flash("Enter username and password.", "error"); return render_template("login.html")
        user = get_user(u)
        if user and check_password_hash(user["password"], p):
            session["user_id"]  = user["id"]
            session["username"] = user["username"]
            session["role"]     = user["role"]
            update_last_login(user["id"])
            flash(f"Welcome back, {u}!", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid credentials.", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("index"))


# ─────────────────────────────────────────────────────────────
#  ADMIN
# ─────────────────────────────────────────────────────────────

@app.route("/dashboard")
@login_required
def dashboard():
    stats   = get_stats()
    scans   = get_recent_scans(20)
    bl      = get_blacklist(15)
    return render_template("dashboard.html",
        stats=stats, scans=scans, blacklist=bl,
        username=session.get("username"), metadata=metadata)


@app.route("/admin/blacklist/add", methods=["POST"])
@login_required
def admin_blacklist_add():
    u = request.form.get("url","").strip()
    r = request.form.get("reason","Manually blacklisted").strip()
    if u:
        ok = add_blacklist(u, r, session.get("username"))
        flash(f"'{u}' added." if ok else "Already blacklisted.", "success" if ok else "warning")
    return redirect(url_for("dashboard"))


@app.route("/api/stats")
@login_required
def api_stats():
    return jsonify(get_stats())


@app.route("/api/model-info")
def api_model_info():
    return jsonify(metadata)


@app.errorhandler(404)
def e404(e): return render_template("404.html"), 404

@app.errorhandler(500)
def e500(e): return jsonify({"error": "Server error"}), 500


if __name__ == "__main__":
    setup()
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host="0.0.0.0", port=port)
