import whois
from models.schema import Entity


def run(target: str) -> list[Entity]:
    entities = []
    try:
        w = whois.whois(target)
    except Exception as e:
        print(f"WHOIS lookup failed for {target}: {e}")
        return entities

    fields = {
        "domain_name": "Domain",
        "registrar": "Registrar",
        "whois_server": "WhoisServer",
        "creation_date": "CreationDate",
        "expiration_date": "ExpirationDate",
        "updated_date": "UpdatedDate",
        "name_servers": "NameServer",
        "emails": "Email",
        "org": "Organization",
        "country": "Country",
        "state": "State",
        "city": "City",
        "registrant": "Registrant",
        "dnssec": "DNSSEC",
    }

    for attr, label in fields.items():
        value = w.get(attr)
        if not value:
            continue

        # Some fields return lists (e.g. name_servers, emails, domain_name)
        if isinstance(value, list):
            for item in value:
                entities.append(Entity(
                    type=label,
                    value=str(item),
                    source="whois"
                ))
        else:
            entities.append(Entity(
                type=label,
                value=str(value),
                source="whois"
            ))

    return entities
