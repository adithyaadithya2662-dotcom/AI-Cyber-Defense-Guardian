def explain_threat(event, ai_result, final_result):
    """
    Generate a human-readable explanation
    for the security threat.
    """

    reasons = []

    event_type = event.get("event_type")
    failed_attempts = event.get("failed_attempts", 0)
    new_ip = event.get("new_ip", 0)
    unusual_time = event.get("unusual_time", 0)

    # Analyze failed login attempts
    if failed_attempts >= 5:
        reasons.append(
            f"🔴 {failed_attempts} failed login attempts detected"
        )

    # Analyze new IP
    if new_ip == 1:
        reasons.append(
            "🔴 Login originated from a new IP address"
        )

    # Analyze unusual time
    if unusual_time == 1:
        reasons.append(
            "🟠 Login occurred at an unusual time"
        )

    # AI anomaly
    if ai_result.get("is_anomaly"):
        reasons.append(
            "🔴 Machine-learning model detected anomalous behavior"
        )

    # Threat type
    if event_type in [
        "failed_login",
        "multiple_failed_logins",
        "suspicious_login"
    ]:
        threat_type = "Possible Brute-Force / Account Compromise"

    elif event_type == "new_ip_login":
        threat_type = "Possible Unauthorized Access"

    else:
        threat_type = "Normal Authentication Activity"

    # Confidence calculation
    confidence = 50

    if ai_result.get("is_anomaly"):
        confidence += 25

    if failed_attempts >= 5:
        confidence += 10

    if new_ip == 1:
        confidence += 5

    if unusual_time == 1:
        confidence += 5

    confidence = min(confidence, 99)

    # Recommendations
    recommendations = []

    if final_result["final_risk_score"] >= 80:
        recommendations.extend([
            "Investigate the source IP address",
            "Enable or verify multi-factor authentication",
            "Review recent account activity",
            "Consider temporarily blocking the suspicious source"
        ])

    elif final_result["final_risk_score"] >= 50:
        recommendations.extend([
            "Monitor the account",
            "Review recent authentication logs"
        ])

    else:
        recommendations.append(
            "Continue monitoring normal activity"
        )

    return {
        "threat_type": threat_type,
        "confidence": confidence,
        "reasons": reasons,
        "recommendations": recommendations
    }