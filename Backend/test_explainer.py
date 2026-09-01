from ai.anomaly_detector import AnomalyDetector
from detection.threat_detector import analyze_event
from detection.risk_engine import calculate_final_risk
from detection.explainer import explain_threat


detector = AnomalyDetector()


# Simulated suspicious activity
event = {
    "event_type": "suspicious_login",
    "username": "admin",
    "ip_address": "192.168.1.50",
    "failed_attempts": 10,
    "new_ip": 1,
    "unusual_time": 1
}


# Rule-based detection
rule_result = analyze_event(event)


# AI detection
ai_result = detector.detect(
    failed_attempts=event["failed_attempts"],
    new_ip=event["new_ip"],
    unusual_time=event["unusual_time"]
)


# Final risk
final_result = calculate_final_risk(
    rule_result["risk_score"],
    ai_result["is_anomaly"],
    ai_result["anomaly_score"]
)


# AI explanation
explanation = explain_threat(
    event,
    ai_result,
    final_result
)


print("\n========== AI SECURITY REPORT ==========")

print("\nThreat Type:")
print(explanation["threat_type"])

print("\nConfidence:")
print(f'{explanation["confidence"]}%')

print("\nWhy is this suspicious?")

for reason in explanation["reasons"]:
    print(reason)

print("\nRecommended Actions:")

for recommendation in explanation["recommendations"]:
    print("🛡️", recommendation)

print("\nFinal Risk:")
print(final_result)

print("\n========================================")