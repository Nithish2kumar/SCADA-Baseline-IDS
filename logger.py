from datetime import datetime

LOG_FILE = "events.log"

def log_event(event_type, severity, source, details):

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    entry = (
        f"[{timestamp}] "
        f"[{severity}] "
        f"[{event_type}] "
        f"Source={source} "
        f"{details}\n"
    )

    with open(LOG_FILE, "a") as f:
        f.write(entry)