"""Knowledge Lite selection: a pure function from a pinned tuple to bundle content.

ADR-0015 **D2** and **D3**. Given the same selection inputs over the same rows,
this module produces byte-identical content, on any host, at any later date --
which is what makes a Lite artifact reproducible by someone who was not there
when it was built.

Two rules carry most of the weight.

**Nothing here reads the clock.** `as_of` is supplied by the caller and pinned
for the whole build. Freshness is computed against that value, never against
"now" (Absolute Constraint 3, applied to the build path). Nor does anything
here read randomness, the environment, or a directory listing, and rows are
ordered by their own canonical bytes rather than by the order they arrived in.

**Ceilings fail closed; they never truncate.** Freshness is a *selection rule*:
it drops rows on a stated, deterministic basis, and that is principled. A
ceiling is a *limit*: if the selected set still exceeds one, the build fails
with a named error rather than quietly shipping a subset. A truncated knowledge
bundle is a bundle that lies about its coverage, and a field node cannot tell
the difference between "this is all there was" and "this is all that fit". The
operator narrows the freshness window or raises the ceiling on purpose; the
builder never decides that silently.

This module performs no I/O and touches no database. It is handed rows and
returns what may be written; the caller does the reading and the writing, so
`local.db` and the active generation are out of reach by construction
(Absolute Constraints 1, 4, 5).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping, Sequence

from .lite_policy import ExportPolicy, apply_export_policy

_MIB = 1024 * 1024


class LiteSelectionError(Exception):
    """Raised when selection inputs are invalid or a ceiling would be exceeded."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


@dataclass(frozen=True)
class LiteCeilings:
    """Hard limits for one capacity profile.

    Re-derived from measurement (ADR-0015 D3). The original values were
    proposed from the consuming products' resource envelopes and assumed
    357.9 bytes per row; measured density for D4-exportable intel-tier data is
    143.7-250.4 B/row, so the row ceiling binds first in every case measured.

    ``max_bytes_per_dataset`` exists because ``max_uncompressed_bytes`` bounds
    only the *total*. Without a per-dataset bound, a selection that respects
    every other ceiling can still put one oversized member in the tar, and the
    reader refuses any single member over ``verify.DEFAULT_MAX_FILE_BYTES``
    (512 MiB) -- so the builder would sign an artifact no conforming reader
    accepts. Keeping this at half the reader's per-file cap leaves the margin
    on the reader's side of the contract, where a future reader can tighten
    without invalidating bundles already signed.
    """

    max_uncompressed_bytes: int
    max_bytes_per_dataset: int
    max_rows_total: int
    max_rows_per_dataset: int
    max_datasets: int
    freshness_window_days: int


#: Neutral artifact profile IDs (ADR-0015 D1). They name a consuming host's
#: resource envelope, never a capability: a `knowledge-lite-32g` artifact grants
#: nothing by itself.
PROFILES: Mapping[str, LiteCeilings] = {
    "knowledge-lite-16g": LiteCeilings(
        max_uncompressed_bytes=192 * _MIB,
        max_bytes_per_dataset=128 * _MIB,
        max_rows_total=750_000,
        max_rows_per_dataset=250_000,
        max_datasets=8,
        freshness_window_days=30,
    ),
    "knowledge-lite-32g": LiteCeilings(
        max_uncompressed_bytes=512 * _MIB,
        max_bytes_per_dataset=256 * _MIB,
        max_rows_total=3_000_000,
        max_rows_per_dataset=1_000_000,
        max_datasets=12,
        freshness_window_days=90,
    ),
}


@dataclass(frozen=True)
class SelectionInputs:
    """The pinned tuple that determines Lite content (ADR-0015 D2)."""

    intel_generation: int
    stats_generation: int
    attack_version: str
    config_hash: str
    profile_id: str
    export_policy_digest: str
    as_of: str

    def as_manifest_block(self) -> dict[str, Any]:
        return {
            "intel_generation": self.intel_generation,
            "stats_generation": self.stats_generation,
            "attack_version": self.attack_version,
            "config_hash": self.config_hash,
            "profile_id": self.profile_id,
            "export_policy_digest": self.export_policy_digest,
            "as_of": self.as_of,
        }


@dataclass(frozen=True)
class LiteSelection:
    """The selected content plus the manifest block that describes it."""

    datasets: Mapping[str, tuple[dict[str, Any], ...]]
    profile_block: Mapping[str, Any]

    def content_bytes(self) -> dict[str, bytes]:
        """Render each dataset to JSONL, in selection order."""
        return {
            dataset: b"".join(_canonical_json_bytes(row) + b"\n" for row in rows)
            for dataset, rows in self.datasets.items()
        }


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _parse_timestamp(value: Any, where: str) -> datetime:
    """Parse an RFC 3339 / ISO 8601 timestamp, requiring an explicit offset.

    A naive timestamp is refused rather than assumed to be UTC: guessing an
    offset here would silently change which rows fall inside the freshness
    window, which is exactly the kind of implicit input this module exists to
    keep out.
    """
    if not isinstance(value, str) or not value:
        raise LiteSelectionError("LITE_TIMESTAMP_INVALID", f"{where}: expected an RFC 3339 string, got {value!r}")
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise LiteSelectionError("LITE_TIMESTAMP_INVALID", f"{where}: {value!r} is not RFC 3339: {exc}") from exc
    if parsed.tzinfo is None:
        raise LiteSelectionError(
            "LITE_TIMESTAMP_INVALID", f"{where}: {value!r} has no UTC offset; a naive timestamp is ambiguous"
        )
    return parsed.astimezone(timezone.utc)


def _validate_inputs(inputs: SelectionInputs) -> LiteCeilings:
    ceilings = PROFILES.get(inputs.profile_id)
    if ceilings is None:
        raise LiteSelectionError(
            "LITE_PROFILE_UNKNOWN",
            f"unknown profile {inputs.profile_id!r}; known profiles: {sorted(PROFILES)}",
        )
    for name in ("attack_version", "config_hash", "export_policy_digest", "as_of"):
        value = getattr(inputs, name)
        if not isinstance(value, str) or not value:
            raise LiteSelectionError("LITE_INPUTS_INCOMPLETE", f"selection input {name!r} must be a non-empty string")
    for name in ("intel_generation", "stats_generation"):
        value = getattr(inputs, name)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise LiteSelectionError(
                "LITE_INPUTS_INCOMPLETE", f"selection input {name!r} must be a non-negative integer"
            )
    return ceilings


def select_lite_content(
    rows_by_dataset: Mapping[str, Iterable[Mapping[str, Any]]],
    *,
    inputs: SelectionInputs,
    policy: ExportPolicy,
    alias_key: bytes,
    scope: str,
    freshness_fields: Mapping[str, str] | None = None,
) -> LiteSelection:
    """Select and project Lite content from the supplied rows.

    `freshness_fields` names, per dataset, the timestamp column the freshness
    window applies to. A dataset absent from it is exempt -- static reference
    material such as ATT&CK techniques does not go stale on a 30-day clock, and
    silently dropping it would be worse than keeping it.

    The export policy's digest must match `inputs.export_policy_digest`: the
    digest is part of what determines the content, so a mismatch means the
    artifact would not describe the rules that produced it.
    """
    ceilings = _validate_inputs(inputs)
    if policy.digest != inputs.export_policy_digest:
        raise LiteSelectionError(
            "LITE_POLICY_DIGEST_MISMATCH",
            f"selection inputs name policy digest {inputs.export_policy_digest!r} "
            f"but the supplied policy digests to {policy.digest!r}",
        )

    as_of = _parse_timestamp(inputs.as_of, "selection input 'as_of'")
    cutoff = as_of - timedelta(days=ceilings.freshness_window_days)
    freshness_fields = dict(freshness_fields or {})

    # Datasets are ordered by name so the manifest and the emitted files do not
    # depend on the caller's mapping order.
    dataset_names = sorted(rows_by_dataset)
    if len(dataset_names) > ceilings.max_datasets:
        raise LiteSelectionError(
            "LITE_CEILING_EXCEEDED",
            f"profile {inputs.profile_id!r} allows {ceilings.max_datasets} datasets, selection has {len(dataset_names)}",
        )

    selected: dict[str, tuple[dict[str, Any], ...]] = {}
    total_rows = 0
    total_bytes = 0

    for dataset in dataset_names:
        freshness_field = freshness_fields.get(dataset)
        projected: list[dict[str, Any]] = []
        for row in rows_by_dataset[dataset]:
            if freshness_field is not None:
                if freshness_field not in row:
                    raise LiteSelectionError(
                        "LITE_FRESHNESS_FIELD_MISSING",
                        f"dataset {dataset!r}: freshness field {freshness_field!r} is not present on a row",
                    )
                seen_at = _parse_timestamp(row[freshness_field], f"dataset {dataset!r} field {freshness_field!r}")
                if seen_at < cutoff:
                    continue
            projected.append(apply_export_policy(policy, dataset, row, alias_key=alias_key, scope=scope))

        # Ordered by canonical bytes: a total order over the projected rows that
        # needs no per-dataset primary-key knowledge and cannot depend on the
        # order the caller happened to yield them in.
        ordered = tuple(sorted(projected, key=_canonical_json_bytes))

        if len(ordered) > ceilings.max_rows_per_dataset:
            raise LiteSelectionError(
                "LITE_CEILING_EXCEEDED",
                f"profile {inputs.profile_id!r} allows {ceilings.max_rows_per_dataset} rows in dataset "
                f"{dataset!r}, selection has {len(ordered)}",
            )

        dataset_bytes = sum(len(_canonical_json_bytes(row)) + 1 for row in ordered)
        # Checked per dataset, not only in the total: one dataset is one tar
        # member, and the reader's cap is per member. A selection well inside
        # the total byte ceiling can still carry a member the reader refuses.
        if dataset_bytes > ceilings.max_bytes_per_dataset:
            raise LiteSelectionError(
                "LITE_CEILING_EXCEEDED",
                f"profile {inputs.profile_id!r} allows {ceilings.max_bytes_per_dataset} uncompressed bytes "
                f"in dataset {dataset!r}, selection has {dataset_bytes}",
            )

        selected[dataset] = ordered
        total_rows += len(ordered)
        total_bytes += dataset_bytes

    if total_rows > ceilings.max_rows_total:
        raise LiteSelectionError(
            "LITE_CEILING_EXCEEDED",
            f"profile {inputs.profile_id!r} allows {ceilings.max_rows_total} rows in total, selection has {total_rows}",
        )
    if total_bytes > ceilings.max_uncompressed_bytes:
        raise LiteSelectionError(
            "LITE_CEILING_EXCEEDED",
            f"profile {inputs.profile_id!r} allows {ceilings.max_uncompressed_bytes} uncompressed bytes, "
            f"selection has {total_bytes}",
        )

    profile_block = {
        "profile_id": inputs.profile_id,
        "selection_inputs": inputs.as_manifest_block(),
        "ceilings": {
            "max_uncompressed_bytes": ceilings.max_uncompressed_bytes,
            "max_bytes_per_dataset": ceilings.max_bytes_per_dataset,
            "max_rows_total": ceilings.max_rows_total,
            "max_rows_per_dataset": ceilings.max_rows_per_dataset,
            "max_datasets": ceilings.max_datasets,
            "freshness_window_days": ceilings.freshness_window_days,
        },
        "counts": {
            "datasets": len(selected),
            "rows": total_rows,
            "uncompressed_bytes": total_bytes,
        },
        # Dataset-level provenance travels with the artifact so a consumer can
        # read all eight D4 roles for any claim: the per-row half comes from the
        # row, this half from here. Recording it once is what lets `decay` and
        # `limitations` be stated at all -- they are the same sentence for every
        # row, and no column holds them.
        "provenance": {
            dataset: {
                "row": dict(sorted(policy.datasets[dataset].provenance.row.items())),
                "dataset": dict(sorted(policy.datasets[dataset].provenance.dataset.items())),
            }
            for dataset in sorted(selected)
        },
    }
    return LiteSelection(datasets=selected, profile_block=profile_block)


def selected_dataset_names(selection: LiteSelection) -> Sequence[str]:
    """Dataset names in emission order."""
    return tuple(sorted(selection.datasets))
