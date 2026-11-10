from pydantic import BaseModel, Field


class Evidence(BaseModel):
    quote: str
    explanation: str


class Behaviour(BaseModel):
    behaviour: str
    attack_technique_id: str | None = None
    attack_technique_name: str | None = None
    confidence: str
    evidence: list[Evidence] = Field(default_factory=list)


class ThreatAnalysis(BaseModel):
    report_title: str
    summary: str
    affected_technologies: list[str]
    threat_actors: list[str]
    behaviours: list[Behaviour]
    uncertainties: list[str]
