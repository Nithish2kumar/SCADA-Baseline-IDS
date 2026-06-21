session_alerts = []

def add_alert(alert):
    session_alerts.append(alert)

def get_alerts():
    return session_alerts

def clear_alerts():
    session_alerts.clear()