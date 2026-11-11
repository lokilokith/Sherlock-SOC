from pydantic import BaseModel, ConfigDict, Field


class InvestigationSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    total: int = Field(ge=0)
    completed: int = Field(ge=0)
    partial: int = Field(ge=0)
    failed: int = Field(ge=0)
    running: int = Field(ge=0)
