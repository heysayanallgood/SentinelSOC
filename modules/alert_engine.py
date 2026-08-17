from datetime import datetime


def calculate_risk(event):
    severity = event.get("severity", "INFO")
    fields = event.get("fields", {})

    score = {
        "INFO": 0,
        "LOW": 15,
        "MEDIUM": 40,
        "HIGH": 70,
        "CRITICAL": 100
    }.get(severity, 0)

    # Additional risk factors
    if event.get("type") == "PERMISSION_DENIED":
        score += 10

    if fields.get("permission") in {
        "execute",
        "write",
        "read",
        "search"
    }:
        score += 5

    if fields.get("app") == "com.termux":
        score += 5

    return min(score, 100)


def create_alert(event):
    score = calculate_risk(event)

    if score >= 90:
        risk = "CRITICAL"
    elif score >= 70:
        risk = "HIGH"
    elif score >= 40:
        risk = "MEDIUM"
    elif score >= 15:
        risk = "LOW"
    else:
        risk = "INFO"

    return {
        "timestamp": event.get("timestamp"),
        "type": event.get("type"),
        "severity": event.get("severity"),
        "risk": risk,
        "risk_score": score,
        "fields": event.get("fields", {}),
        "raw": event.get("raw", "")
    }


if __name__ == "__main__":
    print("SentinelSOC Alert Engine OK")
