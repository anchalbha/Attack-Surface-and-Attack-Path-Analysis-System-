"""
Attack Surface and Attack Path Analysis System
Main Flask Application
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_cors import CORS
import json
import os
import hashlib
from datetime import datetime

from scanner import run_scan
from analyzer import analyze_results
from log_analysis import analyze_logs

app = Flask(__name__)
app.secret_key = "cybersec_secret_2024"
CORS(app)

# Simple JSON-based user storage
USERS_FILE = "users.json"

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


# ─── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json()
    name     = data.get("name", "").strip()
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not name or not email or not password:
        return jsonify({"success": False, "message": "All fields are required."}), 400

    users = load_users()
    if email in users:
        return jsonify({"success": False, "message": "Email already registered."}), 409

    users[email] = {
        "name": name,
        "email": email,
        "password": hash_password(password),
        "created_at": datetime.now().isoformat()
    }
    save_users(users)
    return jsonify({"success": True, "message": "Registration successful!"})


@app.route("/api/login", methods=["POST"])
def login():
    data     = request.get_json()
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")

    users = load_users()
    user  = users.get(email)

    if not user or user["password"] != hash_password(password):
        return jsonify({"success": False, "message": "Invalid credentials."}), 401

    session["user"] = {"name": user["name"], "email": email}
    return jsonify({"success": True, "name": user["name"]})


@app.route("/api/logout", methods=["POST"])
def logout():
    session.pop("user", None)
    return jsonify({"success": True})


@app.route("/api/scan", methods=["POST"])
def scan():
    """Main scan endpoint: runs Nmap, analyzes results, reads logs."""
    data = request.get_json()
    ip   = data.get("ip", "").strip()

    if not ip:
        return jsonify({"success": False, "message": "IP address is required."}), 400

    # Run port scan
    scan_data = run_scan(ip)

    # Analyze ports → vulnerabilities → MITRE ATT&CK → attack paths
    analysis = analyze_results(scan_data)

    # Analyze log files
    log_results = analyze_logs()

    # Combine and return
    response = {
        "success": True,
        "ip": ip,
        "scan": scan_data,
        "analysis": analysis,
        "logs": log_results,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    return jsonify(response)


@app.route("/api/session", methods=["GET"])
def check_session():
    user = session.get("user")
    if user:
        return jsonify({"logged_in": True, "name": user["name"]})
    return jsonify({"logged_in": False})


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
