from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
from pathlib import Path
import os

from simulator import generate_security_event
from detection.threat_detector import analyze_event
from detection.risk_engine import calculate_final_risk
from detection.explainer import explain_threat
from ai.anomaly_detector import AnomalyDetector


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

# Possible locations for the frontend
FRONTEND_DIRS = [
    BASE_DIR,
    BASE_DIR / "frontend",
    BASE_DIR / "static",
    BASE_DIR / "templates"
]

# Find the directory containing index.html
FRONTEND_DIR = None

for directory in FRONTEND_DIRS:
    if (directory / "index.html").exists():
        FRONTEND_DIR = directory
        break

if FRONTEND_DIR is None:
    FRONTEND_DIR = BASE_DIR


# ============================================================
# FLASK
# ============================================================

app = Flask(__name__)

CORS(app)

ai_detector = AnomalyDetector()


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/")
def dashboard():

    index_file = FRONTEND_DIR / "index.html"

    if not index_file.exists():
        return jsonify({
            "error": "Dashboard index.html not found",
            "searched_locations": [
                str(directory / "index.html")
                for directory in FRONTEND_DIRS
            ]
        }), 500

    return send_from_directory(
        str(FRONTEND_DIR),
        "index.html"
    )


# ============================================================
# FRONTEND FILES
# ============================================================

@app.route("/<path:filename>")
def frontend_file(filename):

    # Never interfere with API routes
    if filename.startswith("api/"):
        return jsonify({
            "error": "API endpoint not found"
        }), 404

    requested_file = FRONTEND_DIR / filename

    if requested_file.exists() and requested_file.is_file():

        return send_from_directory(
            str(FRONTEND_DIR),
            filename
        )

    return jsonify({
        "error": "File not found",
        "file": filename
    }), 404


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/health")
def health():

    return jsonify({
        "status": "healthy",
        "service": "AI Cyber Defense Guardian"
    })


# ============================================================
# SECURITY ANALYSIS
# ============================================================

@app.route("/api/analyze")
def analyze_security_event():

    # --------------------------------------------------------
    # Generate security event
    # --------------------------------------------------------

    event = generate_security_event()

    event_type = event.get(
        "event_type",
        "normal_login"
    )


    # --------------------------------------------------------
    # Security indicators
    # --------------------------------------------------------

    if event_type == "normal_login":

        failed_attempts = 0
        new_ip = 0
        unusual_time = 0

    elif event_type == "failed_login":

        failed_attempts = 2
        new_ip = 0
        unusual_time = 0

    elif event_type == "new_ip_login":

        failed_attempts = 1
        new_ip = 1
        unusual_time = 0

    elif event_type == "multiple_failed_logins":

        failed_attempts = 8
        new_ip = 1
        unusual_time = 0

    elif event_type == "suspicious_login":

        failed_attempts = 10
        new_ip = 1
        unusual_time = 1

    else:

        failed_attempts = 0
        new_ip = 0
        unusual_time = 0


    # --------------------------------------------------------
    # Add indicators
    # --------------------------------------------------------

    event["failed_attempts"] = failed_attempts
    event["new_ip"] = new_ip
    event["unusual_time"] = unusual_time


    # --------------------------------------------------------
    # Rule-based detection
    # --------------------------------------------------------

    rule_result = analyze_event(event)


    # --------------------------------------------------------
    # AI detection
    # --------------------------------------------------------

    ai_result = ai_detector.detect(
        failed_attempts,
        new_ip,
        unusual_time
    )


    # --------------------------------------------------------
    # Final risk
    # --------------------------------------------------------

    final_result = calculate_final_risk(
        rule_result["risk_score"],
        ai_result["is_anomaly"],
        ai_result["anomaly_score"]
    )


    # --------------------------------------------------------
    # Explanation
    # --------------------------------------------------------

    explanation = explain_threat(
        event,
        ai_result,
        final_result
    )


    # --------------------------------------------------------
    # Response
    # --------------------------------------------------------

    return jsonify({

        "event": event,

        "rule_analysis": rule_result,

        "ai_analysis": ai_result,

        "final_risk": final_result,

        "explanation": explanation

    })


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":

    port = int(
        os.environ.get("PORT", 5000)
    )

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )