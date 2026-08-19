RISK_SCORES = {
    "normal_login": 5,
    "failed_login": 25,
    "new_ip_login": 45,
    "multiple_failed_logins": 70,
    "suspicious_login": 85
}


def analyze_event(event):
    event_type = event.get("event_type", "unknown")

    risk_score = RISK_SCORES.get(event_type, 0)

    if risk_score >= 80:
        severity = "CRITICAL"
    elif risk_score >= 60:
        severity = "HIGH"
    elif risk_score >= 30:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "risk_score": risk_score,
        "severity": severity
    }