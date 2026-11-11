from typing import Literal

from pydantic import BaseModel, ConfigDict


class RuntimeMode(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["demo", "live"]
    label: str
    provider: str
