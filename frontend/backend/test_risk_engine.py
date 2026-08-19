from detection.threat_detector import analyze_event
from detection.risk_engine import calculate_final_risk
from ai.anomaly_detector import AnomalyDetector


detector = AnomalyDetector()


# Generate a suspicious behavior
ai_result = detector.detect(
    failed_attempts=10,
    new_ip=1,
    unusual_time=1
)


# Example security event
event = {
    "event_type": "suspicious_login",
    "username": "admin",
    "ip_address": "192.168.1.50"
}


# Rule-based analysis
rule_result = analyze_event(event)


# Combine rule + AI
final_result = calculate_final_risk(
    rule_result["risk_score"],
    ai_result["is_anomaly"],
    ai_result["anomaly_score"]
)


print("\n========== SECURITY ANALYSIS ==========")

print("\nEvent:")
print(event)

print("\nRule-Based Analysis:")
print(rule_result)

print("\nAI Analysis:")
print(ai_result)

print("\nFinal Risk Assessment:")
print(final_result)

print("\n=======================================")