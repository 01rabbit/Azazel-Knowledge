"""MITRE Engage catalog + ATT&CK↔Engage mapping feed adapter (ADR-0012).

Full-replace: `engage_activity`/`engage_attack_map` are deleted and
repopulated in a single writer transaction, pinned to `engage_version`.
Engage is catalog/reference data, structurally analogous to ATT&CK
technique metadata, not a scored signal -- it never touches
`ioc`/`ioc_source`, never joins `scoring/`, and never appears in the
7-element replay tuple (see ADR-0012 Constraint 2 / Determinism handling).

`engage_attack_map.technique_id` is deliberately a bare string, not a
foreign key into `attack_technique.technique_id`: ATT&CK and Engage ship
on independent release cadences, so joins at read time are best-effort
string matches, same as `attack_mapping` today (ADR-0012 Schema notes).

Wire format: this adapter's `parse()` expects a *single* already-merged
JSON document -- the Engage activity catalog and the official
ATT&CK<->Engage mapping file, both pinned to one Engage release and
assembled into one document keyed by `engage_version`/`license`/
`activities`/`mappings`:

    {
      "engage_version": "v1.0",
      "license": "MITRE Engage (CC-BY-4.0)",
      "activities": [
        {"activity_id": "EAC0010", "name": "Decoy Content",
         "approach": "Expose", "goal": "Elicit", "description": "..."}
      ],
      "mappings": [
        {"technique_id": "T1595.002", "activity_id": "EAC0010"}
      ]
    }

Producing that single document from MITRE Engage's upstream tarball (two
separate generated files, `data/engage-data-v*.json` and
`data/attack-engage-mapping.json`) is the worker/`azctl feed` invocation's
job, not this adapter's -- out of scope here per ADR-0012 §Adapter, exactly
as `attack.py`'s STIX bundle is handed to it pre-fetched. An activity's own
identifier may arrive as either `activity_id` or `id` upstream; both are
accepted.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from azazel_knowledge.feeds.base import FeedAdapter, FeedError

_ID_MAX_LEN = 64
_TEXT_MAX_LEN = 4096


@dataclass(frozen=True)
class FlatEngageActivity:
    activity_id: str
    name: str
    approach: str
    goal: str | None
    description: str | None


@dataclass(frozen=True)
class FlatEngageMapping:
    technique_id: str
    activity_id: str


@dataclass(frozen=True)
class FlattenedEngage:
    engage_version: str
    license: str | None
    activities: list[FlatEngageActivity] = field(default_factory=list)
    mappings: list[FlatEngageMapping] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.activities) + len(self.mappings)


def _activity_id_of(raw: dict[str, Any]) -> Any:
    return raw.get("activity_id") or raw.get("id")


class EngageAdapter(FeedAdapter):
    full_replace = True

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._license: str | None = None

    def parse(self, raw: bytes) -> FlattenedEngage:
        document = json.loads(raw)
        version_override = self.config.get("engage_version")
        engage_version = str(version_override) if version_override else document.get("engage_version")
        if not engage_version:
            raise FeedError("engage: missing engage_version")

        license_ = document.get("license")
        self._license = license_

        activities: list[FlatEngageActivity] = []
        for raw_activity in document.get("activities", []) or []:
            activities.append(
                FlatEngageActivity(
                    activity_id=_activity_id_of(raw_activity),
                    name=raw_activity.get("name"),
                    approach=raw_activity.get("approach"),
                    goal=raw_activity.get("goal"),
                    description=raw_activity.get("description"),
                )
            )

        mappings: list[FlatEngageMapping] = []
        for raw_mapping in document.get("mappings", []) or []:
            mappings.append(
                FlatEngageMapping(
                    technique_id=raw_mapping.get("technique_id"),
                    activity_id=_activity_id_of(raw_mapping),
                )
            )

        return FlattenedEngage(
            engage_version=str(engage_version),
            license=license_,
            activities=activities,
            mappings=mappings,
        )

    def validate(self, items: FlattenedEngage) -> FlattenedEngage:
        valid_activities: list[FlatEngageActivity] = []
        for a in items.activities:
            if not a.activity_id or not a.name or not a.approach:
                continue
            if len(a.activity_id) > _ID_MAX_LEN:
                continue
            if any(
                isinstance(v, str) and len(v) > _TEXT_MAX_LEN
                for v in (a.name, a.approach, a.goal, a.description)
            ):
                continue
            valid_activities.append(a)

        valid_mappings: list[FlatEngageMapping] = []
        for m in items.mappings:
            if not m.technique_id or not m.activity_id:
                continue
            if len(m.technique_id) > _ID_MAX_LEN or len(m.activity_id) > _ID_MAX_LEN:
                continue
            valid_mappings.append(m)

        return FlattenedEngage(
            engage_version=items.engage_version,
            license=items.license,
            activities=valid_activities,
            mappings=valid_mappings,
        )

    def item_count(self, items: FlattenedEngage) -> int:
        return len(items)

    def apply_batch(self, batch: FlattenedEngage) -> int:
        def txn(conn: Any) -> int:
            conn.execute("DELETE FROM engage_attack_map")
            conn.execute("DELETE FROM engage_activity")
            conn.executemany(
                "INSERT INTO engage_activity (activity_id, name, approach, goal, description, "
                "engage_version) VALUES (?, ?, ?, ?, ?, ?)",
                [
                    (a.activity_id, a.name, a.approach, a.goal, a.description, batch.engage_version)
                    for a in batch.activities
                ],
            )
            conn.executemany(
                "INSERT INTO engage_attack_map (technique_id, activity_id, engage_version) "
                "VALUES (?, ?, ?)",
                [(m.technique_id, m.activity_id, batch.engage_version) for m in batch.mappings],
            )
            return len(batch)

        return self._exec_intel(txn)

    def after_run(self, outcome: Any) -> None:
        if outcome.status == "applied" and self._license and self.intel_writer is not None:
            def txn(conn: Any) -> None:
                conn.execute(
                    "UPDATE feed_state SET license = ? WHERE feed_id = ?",
                    (self._license, self.feed_id),
                )

            self._exec_intel(txn)
