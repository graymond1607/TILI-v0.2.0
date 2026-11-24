from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Optional

@dataclass
class LogEvent:
    source: str
    timestamp: Optional[datetime]
    level: str
    component: str
    message: str
    line_number: int
    file_name: str
    hostname: str = "Unknown"
    device_id: str = "Unknown"
    konnektor_id: str = "Unknown"
    hardware_id: str = "Unknown"
    device_uid: str = "Unknown"
    instance_id: str = "Unknown"
    identity_id: Optional[str] = None
    environment: str = ""
    environment_source: str = ""
    environment_evidence: str = ""

    def to_dict(self):
        result=asdict(self); result["timestamp"]=self.timestamp.isoformat() if self.timestamp else None; return result

@dataclass
class Finding:
    rule_id: str
    source: str
    severity: str
    title: str
    description: str
    recommendation: str
    confidence: str
    line_number: int
    file_name: str
    timestamp: Optional[datetime]
    evidence: str
    category: str = "General"
    hostname: str = "Unknown"
    device_uid: str = "Unknown"
    instance_id: str = "Unknown" 
    device_id: str = "Unknown"
    konnektor_id: str = "Unknown"
    hardware_id: str = "Unknown"
    identity_id: Optional[str] = None
    def to_dict(self):
        result=asdict(self); result["timestamp"]=self.timestamp.isoformat() if self.timestamp else None; return result
