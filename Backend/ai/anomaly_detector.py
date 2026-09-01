from sklearn.ensemble import IsolationForest


class AnomalyDetector:

    def __init__(self):

        self.model = IsolationForest(
            n_estimators=200,
            contamination=0.2,
            random_state=42
        )

        # Normal user behavior
        self.training_data = [
            [1, 0, 0],
            [2, 0, 0],
            [1, 0, 1],
            [2, 0, 1],
            [3, 0, 0],
            [2, 1, 0],
            [1, 0, 0],
            [3, 0, 1],
            [2, 0, 0],
            [1, 0, 0],
            [2, 0, 0],
            [3, 0, 1]
        ]

        self.model.fit(self.training_data)

    def detect(self, failed_attempts, new_ip, unusual_time):

        data = [[
            failed_attempts,
            new_ip,
            unusual_time
        ]]

        prediction = self.model.predict(data)[0]
        anomaly_score = self.model.decision_function(data)[0]

        # Additional security threshold for our demo
        is_anomaly = (
            prediction == -1
            or failed_attempts >= 5
            or (new_ip == 1 and unusual_time == 1)
        )

        return {
            "is_anomaly": bool(is_anomaly),
            "anomaly_score": round(float(anomaly_score), 4)
        }


if __name__ == "__main__":

    detector = AnomalyDetector()

    normal_result = detector.detect(
        failed_attempts=1,
        new_ip=0,
        unusual_time=0
    )

    suspicious_result = detector.detect(
        failed_attempts=10,
        new_ip=1,
        unusual_time=1
    )

    print("Normal activity:")
    print(normal_result)

    print("\nSuspicious activity:")
    print(suspicious_result)