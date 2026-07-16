from core.api import get
from config.api_keys import ABUSEIPDB_KEY


def ip_reputation(ip):

    headers = {
        "Key": ABUSEIPDB_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    r = get(
        "https://api.abuseipdb.com/api/v2/check",
        headers=headers,
        params=params
    )

    if r is None:
        return None

    if r.status_code != 200:
        return None

    return r.json()
