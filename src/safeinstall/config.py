"""Validated scan configuration with AI disabled by default."""

from pydantic import BaseModel, ConfigDict, Field

from safeinstall.analysis.ai_analysis import DEFAULT_AI_MODEL


class ScanConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    ai: bool = False
    ai_model: str = Field(default=DEFAULT_AI_MODEL, min_length=1, max_length=200)
