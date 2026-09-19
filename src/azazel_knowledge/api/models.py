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

from typing import Any, Literal

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
    #: Optional correlation key for the authoritative Defensive State lane
    #: (Knowledge#65). Additive and backward-compatible: a caller that omits it
    #: gets exactly the response it got before, with `reported_defensive_state`
    #: null. It is never a scoring input and never enters the determinism tuple.
    trace_id: str | None = None


class EngageRef(BaseModel):
    """One MITRE Engage catalog activity matched to an advisory technique.

    Additive, advisory-only context (ADR-0012 usage seam, #60): a
    cataloged counter-activity *reference*, never an instruction to
    activate anything. Final authority for any deception/response action
    remains the Azazel-Edge Deterministic Arbiter / AZ-06.
    """

    technique: str
    activity_id: str
    name: str
    approach: str


class RuleRef(BaseModel):
    """One community Sigma/YARA rule matched to an advisory technique.

    Additive, advisory-only context (ADR-0013 usage seam, #61): identity
    and metadata only. NEVER carries `raw_yaml`/`raw_text`/condition logic
    -- nothing executable leaves the process via this field.
    """

    technique: str
    rule_type: str
    rule_id: str
    title: str | None = None
    source_url: str | None = None


class ReportedDefensiveStateFact(BaseModel):
    """One producer's report about its own Defensive State.

    Knowledge advises; it never sets Defensive State. This model carries no
    target, no request, and no transition -- only what was reported, by whom,
    under which decision, and when.

    `reported_state` is a plain string carried exactly as it arrived, and
    `state_vocabulary` names the vocabulary it was reported in. Knowledge does
    not enumerate the values: the canonical vocabulary is Azazel-Fabric's
    (Fabric#14), and a second copy here would drift from it.
    """

    reported_state: str
    state_vocabulary: str
    producer_product: str
    producer_node: str
    trace_id: str
    decision_ref: str
    observed_at: str
    observation_ref: str
    authority_class: Literal["producer_reported_state"] = "producer_reported_state"


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
    engage_refs: list[EngageRef] = Field(default_factory=list)
    rule_refs: list[RuleRef] = Field(default_factory=list)
    #: The **fact lane** (Knowledge#65). What an authoritative producer reported
    #: about its own Defensive State, with provenance -- kept structurally
    #: separate from `recommendation`, which is Knowledge's inference and is
    #: advisory-only. `None` means unknown: nothing was reported, the value was
    #: unreadable, or everything reported is newer than this query. Knowledge
    #: never substitutes a default, because a default would be Knowledge
    #: asserting another product's posture out of its own ignorance.
    reported_defensive_state: ReportedDefensiveStateFact | None = None


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
