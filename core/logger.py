from pathlib import Path

LOG_FILE = Path("logs/activity.log")

def last_logs(limit=5):

    if not LOG_FILE.exists():

        return ["No Activity"]

    with LOG_FILE.open() as f:

        lines = f.readlines()

    return [line.strip() for line in lines[-limit:]]
