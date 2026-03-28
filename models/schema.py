from pydantic import BaseModel
from typing import Optional, Dict, Any

class Entity(BaseModel):
    type: str #e.g., "IP", "Domain", "Email", "Service"
    value: str 
    metadata: Optional[Dict[str, Any]] = {}
    source: str