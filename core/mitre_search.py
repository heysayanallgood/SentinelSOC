from core.mitre_parser import techniques


def get_technique_id(tech):
    refs = tech.get("external_references", [])

    for ref in refs:
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", "")

    return ""


def search_by_id(keyword):
    keyword = keyword.strip().upper()

    for tech in techniques():
        tid = get_technique_id(tech)

        if tid.upper() == keyword:
            return tech

    return None


def search_by_name(keyword):
    keyword = keyword.strip().lower()

    results = []

    for tech in techniques():
        name = tech.get("name", "").lower()

        if keyword in name:
            results.append(tech)

    return results


def search_by_description(keyword):
    keyword = keyword.strip().lower()

    results = []

    for tech in techniques():
        description = tech.get("description", "").lower()

        if keyword in description:
            results.append(tech)

    return results


def search_by_platform(keyword):
    keyword = keyword.strip().lower()

    results = []

    for tech in techniques():

        platforms = tech.get("x_mitre_platforms", [])

        for platform in platforms:

            if keyword in platform.lower():
                results.append(tech)
                break

    return results


def search_by_tactic(keyword):
    keyword = keyword.strip().lower()

    results = []

    for tech in techniques():

        phases = tech.get("kill_chain_phases", [])

        for phase in phases:

            phase_name = phase.get("phase_name", "").lower()

            if keyword in phase_name:
                results.append(tech)
                break

    return results


def search(keyword):
    """
    Compatibility search function.

    Searches:
    1. Exact Technique ID
    2. Technique Name
    3. Description
    """

    keyword = keyword.strip()

    if not keyword:
        return []

    exact = search_by_id(keyword)

    if exact:
        return [exact]

    name_results = search_by_name(keyword)

    if name_results:
        return name_results

    return search_by_description(keyword)
