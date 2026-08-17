from core.api import get
from config.api_keys import VIRUSTOTAL_KEY


def hash_lookup(file_hash):

    headers = {
        "x-apikey": VIRUSTOTAL_KEY
    }

    response = get(
        f"https://www.virustotal.com/api/v3/files/{file_hash}",
        headers=headers
    )

    if response is None:
        return None

    if response.status_code != 200:
        return None

    return response.json()
