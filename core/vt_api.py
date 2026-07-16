import base64

from core.api import get
from config.api_keys import VIRUSTOTAL_KEY


def url_lookup(url):

    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    headers = {
        "x-apikey": VIRUSTOTAL_KEY
    }

    r = get(
        f"https://www.virustotal.com/api/v3/urls/{url_id}",
        headers=headers
    )

    if r is None:
        return None

    if r.status_code != 200:
        return None

    return r.json()
