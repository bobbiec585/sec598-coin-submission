from pydantic import BaseModel, Field


class EvidenceFinding(BaseModel):
    observation: str
    significance: str


class ValidationAssessment(BaseModel):
    behaviour_expected: str
    behaviour_observed: bool
    execution_confirmed: bool
    telemetry_confirmed: bool
    detection_confirmed: bool
    confidence: str
    findings: list[EvidenceFinding] = Field(default_factory=list)
    uncertainties: list[str] = Field(default_factory=list)
    conclusion: str
