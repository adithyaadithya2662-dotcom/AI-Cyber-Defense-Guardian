from simulator import generate_security_event
from detection.threat_detector import analyze_event


for _ in range(10):
    event = generate_security_event()

    result = analyze_event(event)

    print("\nEVENT:")
    print(event)

    print("ANALYSIS:")
    print(result)