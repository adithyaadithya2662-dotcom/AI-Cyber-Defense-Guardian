from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
import os

from simulator import generate_security_event
from detection.threat_detector import analyze_event
from detection.risk_engine import calculate_final_risk
from detection.explainer import explain_threat
from ai.anomaly_detector import AnomalyDetector


# ============================================================
# FLASK APP
# ============================================================

app = Flask(
    __name__,
    static_folder=".",
    static_url_path=""
)

CORS(app)


# ============================================================
# AI DETECTOR
# ============================================================

ai_detector = AnomalyDetector()


# ============================================================
# FRONTEND DASHBOARD
# ============================================================

@app.route("/")
def dashboard():
    """
    Serve the Cyber Defense Guardian dashboard.
    """
    return send_from_directory(
        os.path.dirname(os.path.abspath(__file__)),
        "index.html"
    )


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
# SECURITY ANALYSIS API
# ============================================================

@app.route("/api/analyze")
def analyze_security_event():

    # --------------------------------------------------------
    # 1. Generate security event
    # --------------------------------------------------------

    event = generate_security_event()

    event_type = event.get("event_type", "normal_login")


    # --------------------------------------------------------
    # 2. Convert event type into security indicators
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
    # 3. Add indicators to event
    # --------------------------------------------------------

    event["failed_attempts"] = failed_attempts
    event["new_ip"] = new_ip
    event["unusual_time"] = unusual_time


    # --------------------------------------------------------
    # 4. Rule-based threat detection
    # --------------------------------------------------------

    rule_result = analyze_event(event)


    # --------------------------------------------------------
    # 5. AI anomaly detection
    # --------------------------------------------------------

    ai_result = ai_detector.detect(
        failed_attempts,
        new_ip,
        unusual_time
    )


    # --------------------------------------------------------
    # 6. Final risk calculation
    # --------------------------------------------------------

    final_result = calculate_final_risk(
        rule_result["risk_score"],
        ai_result["is_anomaly"],
        ai_result["anomaly_score"]
    )


    # --------------------------------------------------------
    # 7. Explain the threat
    # --------------------------------------------------------

    explanation = explain_threat(
        event,
        ai_result,
        final_result
    )


    # --------------------------------------------------------
    # 8. Return complete analysis
    # --------------------------------------------------------

    return jsonify({

        "event": event,

        "rule_analysis": rule_result,

        "ai_analysis": ai_result,

        "final_risk": final_result,

        "explanation": explanation

    })


# ============================================================
# RUN SERVER
# ============================================================

if __name__ == "__main__":

    port = int(os.environ.get("PORT", 5000))

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )