import dns.resolver
from models.schema import Entity

async def run(target: str, art: str) -> list[Entity]:
    entities = []
    recordTypes = {"A": "IP4", "MX": "MailXchange", "NS": "NameServer", "TXT": "TextRecord", "CNAME": "CanonicalName", "AAAA": "IP6"}
    if(art):
        recordTypes[art] = art

    for key, value in recordTypes.items():
        try:
            answers = dns.resolver.resolve(target, key)
            for rdata in answers:
                entities.append(Entity(
                    type=value,
                    value=str(rdata),
                    source="dns_lookup"
                ))
        except Exception as e:
            print(f"Error resolving {target}: {e}")
    
    return entities