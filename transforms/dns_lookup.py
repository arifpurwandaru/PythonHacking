import dns.resolver
from models.schema import Entity

async def run(target: str, record_type: str = "A") -> list[Entity]:
    entities = []
    try:
        answers = dns.resolver.resolve(target, record_type)
        for rdata in answers:
            entities.append(Entity(
                type="IP",
                value=str(rdata),
                source="dns_lookup"
            ))
    except Exception as e:
        print(f"Error resolving {target}: {e}")
    return entities