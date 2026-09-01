import os

from flask import Flask, jsonify
from flask_cors import CORS

from simulator import generate_security_event
from detection.threat_detector import analyze_event
from detection.risk_engine import calculate_final_risk
from detection.explainer import explain_threat
from ai.anomaly_detector import AnomalyDetector


app = Flask(__name__)
CORS(app)

# --------------------------------------------------
# Configuration
# --------------------------------------------------

# Use SnapDeploy's PORT if provided.
# Fall back to 5000 for local development.
PORT = int(os.environ.get("PORT", "5000"))

# Create AI detector once when the server starts
ai_detector = AnomalyDetector()


# --------------------------------------------------
# Health check
# --------------------------------------------------

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy",
        "service": "AI Cyber Defense Guardian"
    }), 200


# --------------------------------------------------
# Home
# --------------------------------------------------

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "project": "AI Cyber Defense Guardian",
        "status": "online",
        "message": "Cyber Defense System is running"
    }), 200


# --------------------------------------------------
# Security Analysis
# --------------------------------------------------

@app.route("/api/analyze", methods=["GET"])
def analyze_security_event():

    try:
        # 1. Generate security event
        event = generate_security_event()

        event_type = event.get("event_type", "normal_login")

        # 2. Convert event type into security indicators
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

        # Add calculated indicators to event
        event["failed_attempts"] = failed_attempts
        event["new_ip"] = new_ip
        event["unusual_time"] = unusual_time

        # 3. Rule-based detection
        rule_result = analyze_event(event)

        # 4. AI anomaly detection
        ai_result = ai_detector.detect(
            failed_attempts,
            new_ip,
            unusual_time
        )

        # 5. Final risk calculation
        final_result = calculate_final_risk(
            rule_result["risk_score"],
            ai_result["is_anomaly"],
            ai_result["anomaly_score"]
        )

        # 6. Explain the threat
        explanation = explain_threat(
            event,
            ai_result,
            final_result
        )

        # 7. Return complete analysis
        return jsonify({
            "success": True,
            "event": event,
            "rule_analysis": rule_result,
            "ai_analysis": ai_result,
            "final_risk": final_result,
            "explanation": explanation
        }), 200

    except Exception as e:
        # Return JSON instead of allowing the server to crash
        return jsonify({
            "success": False,
            "error": "Security analysis failed",
            "details": str(e)
        }), 500


# --------------------------------------------------
# Error handlers
# --------------------------------------------------

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "success": False,
        "error": "Endpoint not found"
    }), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        "success": False,
        "error": "Internal server error"
    }), 500


# --------------------------------------------------
# Application entry point
# --------------------------------------------------

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=PORT,
        debug=False,
        threaded=True
    )