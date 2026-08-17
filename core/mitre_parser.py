import json

DATABASE = "assets/mitre/enterprise-attack.json"


def load_database():

    with open(DATABASE, "r", encoding="utf-8") as file:

        data = json.load(file)

    return data["objects"]


def techniques():

    db = load_database()

    result = []

    for obj in db:

        if obj.get("type") == "attack-pattern":

            result.append(obj)

    return result
