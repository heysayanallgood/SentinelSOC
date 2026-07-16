from core.api import get
from config.api_keys import OTX_KEY


def lookup(ioc_type, value):

    headers = {
        "X-OTX-API-KEY": OTX_KEY
    }

    url = f"https://otx.alienvault.com/api/v1/indicators/{ioc_type}/{value}/general"

    r = get(url, headers=headers)

    if r is None:
        return None

    if r.status_code != 200:
        return None

    return r.json()
