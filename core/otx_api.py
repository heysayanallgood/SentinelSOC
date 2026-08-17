from core.api import get
from config.api_keys import OTX_KEY


def lookup(indicator_type, indicator):

    headers = {
        "X-OTX-API-KEY": OTX_KEY
    }

    url = f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{indicator}/general"

    response = get(url, headers=headers)

    if response is None:
        return None

    if response.status_code != 200:
        return None

    return response.json()
