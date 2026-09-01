import random
from datetime import datetime


def generate_security_event():
    event_types = [
        "normal_login",
        "failed_login",
        "multiple_failed_logins",
        "new_ip_login",
        "suspicious_login"
    ]

    event_type = random.choice(event_types)

    event = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "event_type": event_type,
        "username": random.choice([
            "admin",
            "john",
            "alice",
            "developer",
            "guest"
        ]),
        "ip_address": f"192.168.1.{random.randint(2, 254)}"
    }

    return event


if __name__ == "__main__":
    for _ in range(10):
        print(generate_security_event())