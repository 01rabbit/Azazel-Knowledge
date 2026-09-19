"""Knowledge Lite export policy: the deny-by-default field boundary (ADR-0015 D5).

A Lite artifact carries a bounded subset of intel-tier knowledge to a Nexus or
Boot node. What may leave this node is decided here, by an explicit allowlist,
and nowhere else.

Three properties this module exists to guarantee:

**Deny by default.** A dataset the policy does not name exports nothing, and a
field the policy does not list is dropped. A field added to a table by a later
migration is therefore *not* exported until someone adds it to the policy on
purpose. There is deliberately no "export everything except ..." form: a
policy document carrying a denylist-shaped key is rejected outright, because
the safe direction of a schema change must never depend on remembering to
extend a blocklist.

**Deterministic redaction.** `alias` fields are replaced by a keyed
pseudonym. The same value, policy version, alias key, and scope always produce
the same pseudonym, so an export is reproducible and auditable; a different
scope produces a different pseudonym, so aliases cannot be correlated across
missions. A redactor that is not reproducible cannot be replayed or audited,
which is why non-determinism is treated here as a defect rather than a
tolerance.

**A recorded digest.** `ExportPolicy.digest` is a canonical hash of the
normalised policy. It is an input to Lite selection and is recorded in the
bundle manifest, so an artifact states which privacy rules produced it.

Nothing here reads wall-clock time, randomness, the environment, or a
directory listing: applying a policy is a pure function of its arguments
(Absolute Constraint 3). Nothing here writes to a database; the policy decides
what *may* be exported, and the builder does the exporting.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import yaml

#: Keys that would turn an allowlist into a denylist. Present only to be
#: rejected: see the module docstring.
_DENYLIST_SHAPED_KEYS: frozenset[str] = frozenset(
    {"deny", "denylist", "except", "exclude", "excluded", "blocklist", "blacklist", "all"}
)

_ALLOWED_MODES: frozenset[str] = frozenset({"allow", "alias"})
_ALLOWED_FIELD_KEYS: frozenset[str] = frozenset({"name", "mode", "optional"})
_ALLOWED_DATASET_KEYS: frozenset[str] = frozenset({"fields", "provenance"})
_ALLOWED_PROVENANCE_KEYS: frozenset[str] = frozenset({"row", "dataset"})

#: The provenance every exported claim must carry (ADR-0015 D4).
#:
#: Each role is satisfied either per row (mapped to a column) or per dataset
#: (a literal recorded once in the manifest). The split is not a convenience:
#: `freshness` and `expiry` genuinely differ per row, while `decay` and
#: `limitations` are properties of the dataset -- the same sentence for every
#: row in it. Copying such a sentence onto 750,000 rows would consume the byte
#: ceiling to say one thing many times, and the intel schema has no column for
#: them anyway. What D4 requires is that a consumer can read all eight for any
#: claim, not that all eight live in the row.
PROVENANCE_ROLES: tuple[str, ...] = (
    "citation",
    "source",
    "freshness",
    "generation",
    "expiry",
    "decay",
    "confidence_ceiling",
    "limitations",
)
_ALLOWED_ROOT_KEYS: frozenset[str] = frozenset({"version", "datasets"})

#: Hex characters kept from the alias HMAC. 16 hex chars = 64 bits, which is
#: wide enough that collisions are not a practical concern for a bounded Lite
#: bundle while keeping the artifact small.
_ALIAS_HEX_LEN = 16


class LitePolicyError(Exception):
    """Raised when a policy is malformed or a row cannot be exported under it."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


@dataclass(frozen=True)
class FieldRule:
    """One allowlisted field of one dataset."""

    name: str
    mode: str
    optional: bool = False


@dataclass(frozen=True)
class DatasetProvenance:
    """How each D4 provenance role is satisfied for one dataset."""

    row: Mapping[str, str]
    dataset: Mapping[str, str]


@dataclass(frozen=True)
class DatasetPolicy:
    """The complete set of fields exportable from one dataset."""

    dataset: str
    fields: tuple[FieldRule, ...]
    provenance: DatasetProvenance

    def rule(self, name: str) -> FieldRule | None:
        for field in self.fields:
            if field.name == name:
                return field
        return None


@dataclass(frozen=True)
class ExportPolicy:
    """A loaded, validated export policy and its canonical digest."""

    version: str
    datasets: Mapping[str, DatasetPolicy]
    digest: str


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _reject_denylist_shape(node: Any, where: str) -> None:
    """Refuse any mapping key that would express "everything except ...".

    Checked recursively so the shape cannot be smuggled in one level down.
    """
    if isinstance(node, Mapping):
        for key, value in node.items():
            if isinstance(key, str) and key.lower() in _DENYLIST_SHAPED_KEYS:
                raise LitePolicyError(
                    "LITE_POLICY_DENYLIST_SHAPE",
                    f"{where}: {key!r} would express an exclusion; the policy is an allowlist only",
                )
            _reject_denylist_shape(value, f"{where}.{key}")
    elif isinstance(node, (list, tuple)):
        for index, value in enumerate(node):
            _reject_denylist_shape(value, f"{where}[{index}]")


def _require_mapping(value: Any, where: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise LitePolicyError(
            "LITE_POLICY_INVALID", f"{where} must be a mapping, got {type(value).__name__}"
        )
    return value


def _reject_unknown_keys(node: Mapping[str, Any], allowed: frozenset[str], where: str) -> None:
    """Unknown keys are an error, so a typo cannot silently change behaviour.

    A misspelled ``optional`` would otherwise leave the field required, and a
    misspelled ``mode`` would leave it verbatim -- both silent, both wrong.
    """
    unknown = sorted(set(node) - allowed)
    if unknown:
        raise LitePolicyError("LITE_POLICY_INVALID", f"{where}: unknown key(s) {unknown}")


def _parse_provenance(
    raw: Any, rules: tuple[FieldRule, ...], where: str
) -> DatasetProvenance:
    """Validate that all eight D4 roles are covered exactly once.

    Requiring *every* role -- rather than letting a policy list whatever it
    happens to have -- is what stops an unprovenanced claim being exported
    simply because nobody wrote the mapping down.
    """
    prov_where = f"{where}.provenance"
    raw = _require_mapping(raw if raw is not None else {}, prov_where)
    _reject_unknown_keys(raw, _ALLOWED_PROVENANCE_KEYS, prov_where)

    row = _require_mapping(raw.get("row", {}), f"{prov_where}.row")
    dataset = _require_mapping(raw.get("dataset", {}), f"{prov_where}.dataset")

    overlap = sorted(set(row) & set(dataset))
    if overlap:
        raise LitePolicyError(
            "LITE_PROVENANCE_INVALID",
            f"{prov_where}: role(s) {overlap} are satisfied both per row and per dataset; pick one",
        )

    covered = set(row) | set(dataset)
    unknown = sorted(covered - set(PROVENANCE_ROLES))
    if unknown:
        raise LitePolicyError(
            "LITE_PROVENANCE_INVALID", f"{prov_where}: unknown provenance role(s) {unknown}"
        )
    missing = sorted(set(PROVENANCE_ROLES) - covered)
    if missing:
        raise LitePolicyError(
            "LITE_PROVENANCE_INCOMPLETE",
            f"{prov_where}: no provenance declared for role(s) {missing}; ADR-0015 D4 requires all of "
            f"{list(PROVENANCE_ROLES)}",
        )

    by_name = {rule.name: rule for rule in rules}
    for role, column in row.items():
        if not isinstance(column, str) or not column:
            raise LitePolicyError(
                "LITE_PROVENANCE_INVALID", f"{prov_where}.row.{role}: must name a field"
            )
        rule = by_name.get(column)
        if rule is None:
            raise LitePolicyError(
                "LITE_PROVENANCE_INVALID",
                f"{prov_where}.row.{role}: field {column!r} is not in this dataset's allowlist, so it "
                "would never be exported",
            )
        if rule.optional:
            raise LitePolicyError(
                "LITE_PROVENANCE_INVALID",
                f"{prov_where}.row.{role}: field {column!r} is optional; provenance cannot be optional",
            )
        if role == "confidence_ceiling" and rule.mode != "allow":
            raise LitePolicyError(
                "LITE_PROVENANCE_INVALID",
                f"{prov_where}.row.confidence_ceiling: field {column!r} is {rule.mode!r}; aliasing a "
                "confidence destroys the value a consumer must not exceed",
            )
    for role, literal in dataset.items():
        if not isinstance(literal, str) or not literal.strip():
            raise LitePolicyError(
                "LITE_PROVENANCE_INVALID", f"{prov_where}.dataset.{role}: must be a non-empty string"
            )

    return DatasetProvenance(
        row={str(k): str(v) for k, v in row.items()},
        dataset={str(k): str(v) for k, v in dataset.items()},
    )


def parse_export_policy(document: Mapping[str, Any]) -> ExportPolicy:
    """Validate a policy document and compute its digest."""
    document = _require_mapping(document, "export policy")
    _reject_denylist_shape(document, "export policy")
    _reject_unknown_keys(document, _ALLOWED_ROOT_KEYS, "export policy")

    version = document.get("version")
    if not isinstance(version, str) or not version:
        raise LitePolicyError("LITE_POLICY_INVALID", "export policy: 'version' must be a non-empty string")

    raw_datasets = _require_mapping(document.get("datasets", {}), "export policy: 'datasets'")
    if not raw_datasets:
        raise LitePolicyError(
            "LITE_POLICY_INVALID", "export policy: 'datasets' must name at least one dataset"
        )

    datasets: dict[str, DatasetPolicy] = {}
    normalised: dict[str, Any] = {}
    for dataset_name, raw_dataset in raw_datasets.items():
        if not isinstance(dataset_name, str) or not dataset_name:
            raise LitePolicyError("LITE_POLICY_INVALID", "export policy: dataset names must be non-empty strings")
        where = f"export policy: datasets.{dataset_name}"
        raw_dataset = _require_mapping(raw_dataset, where)
        _reject_unknown_keys(raw_dataset, _ALLOWED_DATASET_KEYS, where)

        raw_fields = raw_dataset.get("fields")
        if not isinstance(raw_fields, list) or not raw_fields:
            raise LitePolicyError("LITE_POLICY_INVALID", f"{where}: 'fields' must be a non-empty list")

        rules: list[FieldRule] = []
        seen: set[str] = set()
        for index, raw_field in enumerate(raw_fields):
            field_where = f"{where}.fields[{index}]"
            raw_field = _require_mapping(raw_field, field_where)
            _reject_unknown_keys(raw_field, _ALLOWED_FIELD_KEYS, field_where)

            name = raw_field.get("name")
            if not isinstance(name, str) or not name:
                raise LitePolicyError("LITE_POLICY_INVALID", f"{field_where}: 'name' must be a non-empty string")
            if name in seen:
                raise LitePolicyError("LITE_POLICY_INVALID", f"{where}: field {name!r} listed more than once")
            seen.add(name)

            mode = raw_field.get("mode", "allow")
            if mode not in _ALLOWED_MODES:
                raise LitePolicyError(
                    "LITE_POLICY_INVALID",
                    f"{field_where}: 'mode' must be one of {sorted(_ALLOWED_MODES)}, got {mode!r}",
                )

            optional = raw_field.get("optional", False)
            if not isinstance(optional, bool):
                raise LitePolicyError("LITE_POLICY_INVALID", f"{field_where}: 'optional' must be a boolean")

            rules.append(FieldRule(name=name, mode=mode, optional=optional))

        # Sorted by field name so the digest depends on the policy's meaning,
        # never on the order it happened to be written in.
        ordered = tuple(sorted(rules, key=lambda rule: rule.name))
        provenance = _parse_provenance(raw_dataset.get("provenance"), ordered, where)
        datasets[dataset_name] = DatasetPolicy(
            dataset=dataset_name, fields=ordered, provenance=provenance
        )
        normalised[dataset_name] = {
            "fields": [
                {"name": rule.name, "mode": rule.mode, "optional": rule.optional} for rule in ordered
            ],
            "provenance": {
                "row": dict(sorted(provenance.row.items())),
                "dataset": dict(sorted(provenance.dataset.items())),
            },
        }

    digest = hashlib.sha256(
        _canonical_json_bytes({"version": version, "datasets": normalised})
    ).hexdigest()
    return ExportPolicy(version=version, datasets=datasets, digest=digest)


def load_export_policy(path: str | Path) -> ExportPolicy:
    """Load and validate an export policy from a YAML file."""
    path = Path(path)
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise LitePolicyError("LITE_POLICY_MISSING", f"export policy not found: {path}") from exc
    except yaml.YAMLError as exc:
        raise LitePolicyError("LITE_POLICY_INVALID", f"export policy is not valid YAML: {exc}") from exc
    if document is None:
        raise LitePolicyError("LITE_POLICY_INVALID", f"export policy is empty: {path}")
    return parse_export_policy(document)


def alias_value(value: Any, *, alias_key: bytes, scope: str, dataset: str, field: str) -> str:
    """Return the deterministic pseudonym for one value.

    Keyed by `alias_key` and bound to `scope`, `dataset`, and `field`, so the
    same subject maps to different pseudonyms in different scopes and cannot be
    correlated across them. The components are length-prefixed rather than
    concatenated so that no two different tuples can produce the same message.
    """
    mac = hmac.new(alias_key, digestmod=hashlib.sha256)
    for part in (scope, dataset, field, "" if value is None else str(value)):
        encoded = part.encode("utf-8")
        mac.update(str(len(encoded)).encode("ascii"))
        mac.update(b":")
        mac.update(encoded)
        mac.update(b"\x00")
    return f"az-{mac.hexdigest()[:_ALIAS_HEX_LEN]}"


def apply_export_policy(
    policy: ExportPolicy,
    dataset: str,
    row: Mapping[str, Any],
    *,
    alias_key: bytes,
    scope: str,
) -> dict[str, Any]:
    """Project one row down to what the policy allows to be exported.

    A dataset the policy does not name is refused rather than silently emptied:
    exporting from it is a build error, not a no-op. A field the policy does
    not list is dropped without comment -- that is the allowlist working, and it
    is what makes a newly added column safe by default. A field the policy
    requires but the row does not carry is refused, because a policy that no
    longer matches its data must not quietly produce a thinner artifact.
    """
    dataset_policy = policy.datasets.get(dataset)
    if dataset_policy is None:
        raise LitePolicyError(
            "LITE_DATASET_NOT_ALLOWED", f"dataset {dataset!r} is not named by export policy {policy.version!r}"
        )
    if not alias_key:
        raise LitePolicyError("LITE_ALIAS_KEY_MISSING", "an alias key is required to apply an export policy")
    if not scope:
        raise LitePolicyError("LITE_SCOPE_MISSING", "an alias scope is required to apply an export policy")

    provenance_columns = {column: role for role, column in dataset_policy.provenance.row.items()}
    exported: dict[str, Any] = {}
    for rule in dataset_policy.fields:
        if rule.name not in row:
            if rule.optional:
                continue
            raise LitePolicyError(
                "LITE_FIELD_MISSING",
                f"dataset {dataset!r}: policy requires field {rule.name!r}, row does not carry it",
            )
        value = row[rule.name]
        if rule.name in provenance_columns and value is None:
            raise LitePolicyError(
                "LITE_PROVENANCE_MISSING",
                f"dataset {dataset!r}: field {rule.name!r} carries provenance "
                f"({provenance_columns[rule.name]}) but is null on this row; the claim cannot be "
                "exported without it",
            )
        if rule.mode == "alias":
            exported[rule.name] = alias_value(
                value, alias_key=alias_key, scope=scope, dataset=dataset, field=rule.name
            )
        else:
            exported[rule.name] = value
    return exported
