"""Pydantic request/response models mirroring `docs/api.md` (design S4).

FastAPI + pydantic are confined to this package; every other module in
the codebase is framework-free. Nested structures that the correlation
pipeline and scoring engine already emit as plain dicts (`reason[]`,
`threat_context`, `recommendation`, ...) are typed loosely
(`dict[str, Any]` / `list[dict[str, Any]]`) here rather than re-modeled
field-by-field -- the pipeline dataclasses in `correlate/pipeline.py`
and `scoring/compute.py` are the authoritative shape, and duplicating
their fields into a second, hand-maintained pydantic schema would be a
drift hazard rather than a safety net.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

ADVISORY_NOTICE = (
    "Recommendation is advisory. Final authority: Azazel-Edge Deterministic Arbiter."
)


class IocSearchRequest(BaseModel):
    type: str
    value: str


class Ja3Ja4SearchRequest(BaseModel):
    value: str


class SearchBasis(BaseModel):
    groups: list[str] = Field(default_factory=list)
    source_count: int = 0
    freshest_last_seen: str | None = None


class SearchResponse(BaseModel):
    match: bool
    confidence: float
    confidence_reason: list[dict[str, Any]]
    sources: list[str]
    first_seen: str | None
    last_seen: str | None
    source_freshness_days: float | None
    basis: SearchBasis
    confidence_basis: str | None = None


class ContextEntity(BaseModel):
    type: str
    value: str


class ContextApiRequest(BaseModel):
    entities: list[ContextEntity] = Field(default_factory=list)
    event: dict[str, Any] = Field(default_factory=dict)
    edge_id: str = ""
    actor_key: str = ""
    event_id: str | None = None


class ContextResponse(BaseModel):
    threat_context: dict[str, Any]
    threat_score: float
    confidence: float
    reason: list[dict[str, Any]]
    confidence_reason: list[dict[str, Any]]
    recommendation: dict[str, Any]
    source_freshness: dict[str, Any]
    advisory_notice: str = ADVISORY_NOTICE
    advisory_id: str
    multi_ioc_scope: dict[str, Any]


class IngestAcceptedResponse(BaseModel):
    batch_id: str


class IngestStatusResponse(BaseModel):
    batch_id: str
    accepted: str
    line_count: int
    valid: int
    invalid: list[dict[str, Any]]
    drained: bool


class AdminAcceptedResponse(BaseModel):
    status: str = "queued"
    detail: str | None = None
