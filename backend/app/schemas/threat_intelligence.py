from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.alerts import EvidenceReference


IndicatorType = Literal["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"]
Verdict = Literal["malicious", "suspicious", "benign", "unknown"]
LookupStatus = Literal["available", "unavailable", "unknown"]


class Indicator(BaseModel):
    model_config = ConfigDict(extra="forbid")

    indicator_type: IndicatorType
    normalized_value: str
    original_value: str
    source_event_ids: list[str] = Field(min_length=1)
    source_fields: list[str] = Field(min_length=1)


class ThreatIntelLookup(BaseModel):
    model_config = ConfigDict(extra="forbid")

    indicator_type: IndicatorType
    normalized_value: str
    provider_name: str
    verdict: Verdict
    reputation_score: float | None = Field(default=None, ge=0, le=100)
    confidence: float | None = Field(default=None, ge=0, le=1)
    analysis_stats: dict[str, int] = Field(default_factory=dict)
    evidence_summary: str
    source_reference: str | None = None
    lookup_timestamp: datetime
    lookup_status: LookupStatus


class ThreatIntelIndicatorResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    indicator_type: IndicatorType
    normalized_value: str
    original_value: str
    source_event_ids: list[str] = Field(min_length=1)
    source_fields: list[str] = Field(min_length=1)
    provider_name: str
    verdict: Verdict
    reputation_score: float | None = Field(default=None, ge=0, le=100)
    confidence: float | None = Field(default=None, ge=0, le=1)
    analysis_stats: dict[str, int] = Field(default_factory=dict)
    evidence_summary: str
    source_reference: str | None = None
    lookup_timestamp: datetime
    lookup_status: LookupStatus
    cached: bool = Field(default=False)
    model_config = ConfigDict(extra="forbid")

    indicator_type: IndicatorType
    normalized_value: str
    original_value: str
    source_event_ids: list[str] = Field(min_length=1)
    source_fields: list[str] = Field(min_length=1)
    provider_name: str
    verdict: Verdict
    reputation_score: float | None = Field(default=None, ge=0, le=100)
    confidence: float | None = Field(default=None, ge=0, le=1)
    evidence_summary: str
    source_reference: str | None = None
    lookup_timestamp: datetime
    lookup_status: LookupStatus


class ThreatIntelligenceResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alert_id: str
    investigation_summary: str
    indicators: list[ThreatIntelIndicatorResult] = Field(min_length=1)
    missing_information: list[str] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)
    evidence_references: list[EvidenceReference] = Field(min_length=1)


class ManualIOCRequest(BaseModel):
    indicator_type: Literal["auto", "ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"] = "auto"
    value: str = Field(min_length=1, max_length=4096)
