import requests


def get(url, headers=None, params=None):

    try:

        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=15
        )

        return response

    except Exception:

        return None
