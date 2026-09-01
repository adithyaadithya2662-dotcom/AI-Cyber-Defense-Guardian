from flask import Flask, jsonify
from flask_cors import CORS

from simulator import generate_security_event
from detection.threat_detector import analyze_event
from detection.risk_engine import calculate_final_risk
from detection.explainer import explain_threat
from ai.anomaly_detector import AnomalyDetector


app = Flask(__name__)
CORS(app)

# Create AI detector once when the server starts
ai_detector = AnomalyDetector()


@app.route("/")
def home():
    return jsonify({
        "project": "AI Cyber Defense Guardian",
        "status": "online",
        "message": "Cyber Defense System is running"
    })


@app.route("/api/analyze")
def analyze_security_event():

    # 1. Generate security event
    event = generate_security_event()

    event_type = event["event_type"]

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

    event["failed_attempts"] = failed_attempts
    event["new_ip"] = new_ip
    event["unusual_time"] = unusual_time

    # 2. Rule-based detection
    rule_result = analyze_event(event)

    # 3. AI anomaly detection
    ai_result = ai_detector.detect(
        failed_attempts,
        new_ip,
        unusual_time
    )

    # 4. Final risk calculation
    final_result = calculate_final_risk(
        rule_result["risk_score"],
        ai_result["is_anomaly"],
        ai_result["anomaly_score"]
    )

    # 5. Explain the threat
    explanation = explain_threat(
        event,
        ai_result,
        final_result
    )

    # 6. Return complete security analysis
    return jsonify({
        "event": event,
        "rule_analysis": rule_result,
        "ai_analysis": ai_result,
        "final_risk": final_result,
        "explanation": explanation
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)