from typing import Any

from pydantic import BaseModel, Field


class ThreatEvent(BaseModel):
    id: str
    type: str
    severity: str
    source_ip: str | None = None
    destination_ip: str | None = None
    timestamp: str | None = None
    description: str
    details: dict[str, Any] = Field(default_factory=dict)


class ThreatAnalysisRequest(BaseModel):
    input_path: str


class ThreatAnalysisResponse(BaseModel):
    input_path: str
    threat_count: int
    threats: list[ThreatEvent]


class HealthResponse(BaseModel):
    status: str

