from datetime import datetime

def print_alert(
        alert_type,
        severity,
        source,
        destination,
        function_code,
        details,
        actions):

    print("\n" + "=" * 60)
    print("SCADA IDS ALERT")
    print("=" * 60)

    print(f"Alert Type  : {alert_type}")
    print(f"Severity    : {severity}")
    print(f"Source IP   : {source}")
    print(f"Target IP   : {destination}")
    print(f"Function    : {function_code}")
    print(f"Time        : {datetime.now()}")

    print("-" * 60)

    print("Details:")
    print(details)

    print("-" * 60)

    print("Recommended Actions:")

    for num, action in enumerate(actions, 1):
        print(f"{num}. {action}")

    print("=" * 60)