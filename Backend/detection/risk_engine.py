def calculate_final_risk(rule_score, ai_anomaly, anomaly_score):
    """
    Combine rule-based risk and AI anomaly detection
    into one final security risk score.
    """

    final_score = rule_score

    # AI detected unusual behavior
    if ai_anomaly:
        final_score += 15

    # Very unusual ML behavior
    if anomaly_score < -0.05:
        final_score += 10

    # Keep score between 0 and 100
    final_score = min(final_score, 100)

    # Determine final severity
    if final_score >= 80:
        severity = "CRITICAL"
    elif final_score >= 60:
        severity = "HIGH"
    elif final_score >= 30:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "final_risk_score": final_score,
        "severity": severity
    }
