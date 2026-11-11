from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


GroundTruth = Literal["malicious", "benign"]
Classification = Literal["TP", "FP", "FN", "TN"]


class ValidationRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str
    name: str
    version: str


class ValidationDataset(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dataset_id: str
    version: str
    description: str
    case_count: int


class ValidationCaseResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str
    scenario: str
    description: str
    ground_truth: GroundTruth
    detected: bool
    expected_behavior: str
    actual_behavior: str
    matched_conditions: list[str]
    failed_conditions: list[str]
    missing_fields: list[str]
    observability: Literal["available", "missing", "not_applicable"]
    classification: Classification
    event_fields: dict[str, object]


class ValidationMetrics(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tp: int = Field(ge=0)
    fp: int = Field(ge=0)
    fn: int = Field(ge=0)
    tn: int = Field(ge=0)
    precision: float | None = None
    recall: float | None = None
    f1: float | None = None
    specificity: float | None = None
    accuracy: float | None = None


class ValidationRun(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str
    rule: ValidationRule
    dataset: ValidationDataset
    rule_hash: str
    dataset_hash: str
    executed_at: datetime
    metrics: ValidationMetrics
    cases: list[ValidationCaseResult]
