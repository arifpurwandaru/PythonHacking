import shodan
import os
from models.schema import Entity
from typing import List


def run_shodan_ip(target: str) -> List[Entity]:
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
    if not SHODAN_API_KEY:
        print("Shodan API key not found. Please set the SHODAN_API_KEY environment variable.")
        return []
    
    api = shodan.Shodan(SHODAN_API_KEY)
    entities = []
    
    try:
        # host_info = api.host(target) # This for paid version
        host_info = api.search(f"ip:{target}") # This for free version
        for item in host_info.get('data', []):
            entities.append(Entity(
                type="Service",
                value=f"{item.get('port')}/{item.get('transport')}",
                source="shodan"
            ))
    except shodan.APIError as e:
        print(f"Shodan API error: {e}")
    
    return entities