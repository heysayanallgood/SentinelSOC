from core.api import get

def cve_lookup(cve):

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"

    response = get(url)

    if response is None:
        return None

    if response.status_code != 200:
        return None

    return response.json()
