from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG_DIR = REPO_ROOT / "config"
DEFAULT_DOCS_DIR = REPO_ROOT / "docs"
DEFAULT_ALLOWLIST_PATH = REPO_ROOT / "tools" / "docs-sync-allowlist.yaml"
RELATIVE_DOC_PREFIX = "docs"


@dataclass(frozen=True, order=True)
class Mismatch:
    doc: str
    check: str
    key: str
    expected: Any
    actual: Any
    message: str


@dataclass(frozen=True)
class WarningRecord:
    kind: str
    doc: str
    check: str
    key: str
    message: str


@dataclass(frozen=True)
class CheckResult:
    mismatches: list[Mismatch]
    warnings: list[WarningRecord]
    exit_code: int


def _load_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a YAML mapping")
    return data


def _relative_doc_name(path: Path, docs_dir: Path) -> str:
    return f"{RELATIVE_DOC_PREFIX}/{path.relative_to(docs_dir).as_posix()}"


def _make_mismatch(
    *,
    doc: str,
    check: str,
    key: str,
    expected: Any,
    actual: Any,
    message: str,
) -> Mismatch:
    return Mismatch(
        doc=doc,
        check=check,
        key=key,
        expected=expected,
        actual=actual,
        message=message,
    )


def _parse_markdown_table(
    text: str,
    *,
    headers: tuple[str, ...],
) -> dict[str, float] | None:
    lines = text.splitlines()
    for index, line in enumerate(lines):
        cells = [cell.strip() for cell in line.strip().split("|")[1:-1]]
        if tuple(cells) != headers:
            continue
        if index + 1 >= len(lines):
            return {}
        separator = lines[index + 1].strip()
        if not separator.startswith("|"):
            return {}
        rows: dict[str, float] = {}
        row_index = index + 2
        while row_index < len(lines):
            row_line = lines[row_index].strip()
            if not row_line.startswith("|"):
                break
            row_cells = [cell.strip() for cell in row_line.split("|")[1:-1]]
            if len(row_cells) != len(headers):
                break
            try:
                rows[row_cells[0]] = float(row_cells[1])
            except ValueError as exc:
                raise ValueError(
                    f"invalid numeric value {row_cells[1]!r} in markdown table row {row_cells[0]!r}"
                ) from exc
            row_index += 1
        return rows
    return None


def _extract_scoring_weights(doc_path: Path) -> dict[str, float]:
    text = doc_path.read_text(encoding="utf-8")
    table = _parse_markdown_table(
        text,
        headers=("Component", "Weight", "Source"),
    )
    if table is None:
        raise ValueError("weights table '| Component | Weight | Source |' not found")
    return table


def _extract_freshness(doc_path: Path) -> tuple[int, float]:
    text = doc_path.read_text(encoding="utf-8")
    match = re.search(
        r"half-life\s+(\d+)\s+days,\s+floor\s+([0-9]+(?:\.[0-9]+)?)",
        text,
        flags=re.IGNORECASE,
    )
    if match is None:
        raise ValueError("freshness text 'half-life N days, floor F' not found")
    return int(match.group(1)), float(match.group(2))


def _extract_reason_weights(doc_path: Path) -> dict[str, float]:
    text = doc_path.read_text(encoding="utf-8")
    fences = re.findall(r"```json\s*(.*?)\s*```", text, flags=re.DOTALL)
    if not fences:
        raise ValueError("no JSON code fences found")

    for block in fences:
        try:
            payload = json.loads(block)
        except json.JSONDecodeError:
            reason_match = re.search(r'"reason"\s*:\s*\[(.*?)\]', block, flags=re.DOTALL)
            if reason_match is None:
                continue
            return _parse_reason_entries(reason_match.group(1))
        if not isinstance(payload, dict) or "reason" not in payload:
            continue
        reason = payload["reason"]
        if not isinstance(reason, list):
            raise ValueError("JSON example field 'reason' must be an array")
        return _parse_reason_list(reason)

    raise ValueError("no JSON code fence containing a reason[] example was found")


def _parse_reason_entries(reason_block: str) -> dict[str, float]:
    objects = re.findall(r"\{[^{}]*\}", reason_block, flags=re.DOTALL)
    if not objects:
        raise ValueError("reason[] example was found but no JSON objects could be extracted")
    entries = []
    for index, obj_text in enumerate(objects):
        try:
            entries.append(json.loads(obj_text))
        except json.JSONDecodeError as exc:
            raise ValueError(f"reason[{index}] is not valid JSON") from exc
    return _parse_reason_list(entries)


def _parse_reason_list(reason: list[Any]) -> dict[str, float]:
    weights: dict[str, float] = {}
    for index, entry in enumerate(reason):
        if not isinstance(entry, dict):
            raise ValueError(f"reason[{index}] must be an object")
        weight_value = entry.get("config_weight", entry.get("weight"))
        if "component" not in entry or weight_value is None:
            raise ValueError(
                f"reason[{index}] must include 'component' and 'config_weight' or 'weight'"
            )
        component = entry["component"]
        if not isinstance(component, str):
            raise ValueError(f"reason[{index}].component must be a string")
        try:
            weights[component] = float(weight_value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"reason[{index}].config_weight/weight must be numeric") from exc
    return weights


def _extract_confidence_weights(doc_path: Path) -> dict[str, float] | None:
    text = doc_path.read_text(encoding="utf-8")
    headings = list(
        re.finditer(r"^(#{1,6})\s+.*confidence.*$", text, flags=re.IGNORECASE | re.MULTILINE)
    )
    if not headings:
        return None

    lines = text.splitlines()
    for match in headings:
        start_line = text[: match.start()].count("\n")
        section_lines: list[str] = []
        for line in lines[start_line + 1 :]:
            if re.match(r"^#{1,6}\s+", line):
                break
            section_lines.append(line)
        section_text = "\n".join(section_lines)
        table = _parse_markdown_table(
            section_text,
            headers=("Driver", "Weight", "Description"),
        )
        if table is not None:
            return table
        table = _parse_markdown_table(
            section_text,
            headers=("Component", "Weight", "Description"),
        )
        if table is not None:
            return table
    return None


def _load_allowlist(path: Path) -> list[dict[str, str]]:
    data = _load_yaml(path)
    raw_entries = data.get("known_diffs", [])
    if raw_entries is None:
        raw_entries = []
    if not isinstance(raw_entries, list):
        raise ValueError(f"{path} key 'known_diffs' must be a list")
    entries: list[dict[str, str]] = []
    for index, entry in enumerate(raw_entries):
        if not isinstance(entry, dict):
            raise ValueError(f"{path} known_diffs[{index}] must be a mapping")
        normalized = {}
        for field in ("doc", "check", "key", "reason"):
            value = entry.get(field)
            if not isinstance(value, str):
                raise ValueError(f"{path} known_diffs[{index}].{field} must be a string")
            normalized[field] = value
        entries.append(normalized)
    return entries


def _compare_exact(
    *,
    doc: str,
    check: str,
    expected: dict[str, float],
    actual: dict[str, float],
) -> list[Mismatch]:
    mismatches: list[Mismatch] = []
    for key in sorted(expected):
        if key not in actual:
            mismatches.append(
                _make_mismatch(
                    doc=doc,
                    check=check,
                    key=key,
                    expected=expected[key],
                    actual=None,
                    message=f"{doc} is missing {key!r} in {check}",
                )
            )
            continue
        if actual[key] != expected[key]:
            mismatches.append(
                _make_mismatch(
                    doc=doc,
                    check=check,
                    key=key,
                    expected=expected[key],
                    actual=actual[key],
                    message=f"{doc} has drift for {key!r} in {check}",
                )
            )
    for key in sorted(set(actual) - set(expected)):
        mismatches.append(
            _make_mismatch(
                doc=doc,
                check=check,
                key=key,
                expected=None,
                actual=actual[key],
                message=f"{doc} has undocumented extra entry {key!r} in {check}",
            )
        )
    return mismatches


def _compare_subset(
    *,
    doc: str,
    check: str,
    expected: dict[str, float],
    actual: dict[str, float],
) -> list[Mismatch]:
    mismatches: list[Mismatch] = []
    for key in sorted(actual):
        if key not in expected:
            mismatches.append(
                _make_mismatch(
                    doc=doc,
                    check=check,
                    key=key,
                    expected=None,
                    actual=actual[key],
                    message=f"{doc} has unknown component {key!r} in {check}",
                )
            )
            continue
        if actual[key] != expected[key]:
            mismatches.append(
                _make_mismatch(
                    doc=doc,
                    check=check,
                    key=key,
                    expected=expected[key],
                    actual=actual[key],
                    message=f"{doc} has drift for {key!r} in {check}",
                )
            )
    return mismatches


def _partition_mismatches(
    mismatches: list[Mismatch],
    allowlist: list[dict[str, str]],
) -> tuple[list[Mismatch], list[WarningRecord]]:
    allow_index = {
        (entry["doc"], entry["check"], entry["key"]): entry["reason"] for entry in allowlist
    }
    warnings: list[WarningRecord] = []
    remaining: list[Mismatch] = []
    matched_keys: set[tuple[str, str, str]] = set()

    for mismatch in sorted(mismatches):
        mismatch_key = (mismatch.doc, mismatch.check, mismatch.key)
        reason = allow_index.get(mismatch_key)
        if reason is None:
            remaining.append(mismatch)
            continue
        matched_keys.add(mismatch_key)
        warnings.append(
            WarningRecord(
                kind="allowlisted",
                doc=mismatch.doc,
                check=mismatch.check,
                key=mismatch.key,
                message=f"{mismatch.message} (allowlisted: {reason})",
            )
        )

    for entry in sorted(allowlist, key=lambda item: (item["doc"], item["check"], item["key"])):
        entry_key = (entry["doc"], entry["check"], entry["key"])
        if entry_key in matched_keys:
            continue
        warnings.append(
            WarningRecord(
                kind="stale",
                doc=entry["doc"],
                check=entry["check"],
                key=entry["key"],
                message=f"stale allowlist entry; mismatch no longer exists ({entry['reason']})",
            )
        )

    warnings.sort(key=lambda item: (item.kind, item.doc, item.check, item.key))
    return remaining, warnings


def run_check(config_dir: str | Path, docs_dir: str | Path, allowlist_path: str | Path) -> CheckResult:
    config_dir = Path(config_dir)
    docs_dir = Path(docs_dir)
    allowlist_path = Path(allowlist_path)

    config = _load_yaml(config_dir / "scoring.yaml")
    weights = config["weights"]
    confidence_weights = config["confidence_weights"]
    freshness = config["freshness"]

    scoring_doc = docs_dir / "scoring.md"
    api_doc = docs_dir / "api.md"

    mismatches: list[Mismatch] = []

    scoring_doc_name = _relative_doc_name(scoring_doc, docs_dir)
    api_doc_name = _relative_doc_name(api_doc, docs_dir)

    try:
        doc_weights = _extract_scoring_weights(scoring_doc)
    except ValueError as exc:
        mismatches.append(
            _make_mismatch(
                doc=scoring_doc_name,
                check="weights_table",
                key="table",
                expected=sorted(weights),
                actual=None,
                message=str(exc),
            )
        )
    else:
        mismatches.extend(
            _compare_exact(
                doc=scoring_doc_name,
                check="weights_table",
                expected=weights,
                actual=doc_weights,
            )
        )

    try:
        half_life_days, floor = _extract_freshness(scoring_doc)
    except ValueError as exc:
        mismatches.append(
            _make_mismatch(
                doc=scoring_doc_name,
                check="freshness",
                key="freshness",
                expected={
                    "half_life_days": freshness["half_life_days"],
                    "floor": freshness["floor"],
                },
                actual=None,
                message=str(exc),
            )
        )
    else:
        if half_life_days != freshness["half_life_days"]:
            mismatches.append(
                _make_mismatch(
                    doc=scoring_doc_name,
                    check="freshness",
                    key="half_life_days",
                    expected=freshness["half_life_days"],
                    actual=half_life_days,
                    message=f"{scoring_doc_name} has drift for freshness half_life_days",
                )
            )
        if floor != freshness["floor"]:
            mismatches.append(
                _make_mismatch(
                    doc=scoring_doc_name,
                    check="freshness",
                    key="floor",
                    expected=freshness["floor"],
                    actual=floor,
                    message=f"{scoring_doc_name} has drift for freshness floor",
                )
            )

    try:
        reason_weights = _extract_reason_weights(api_doc)
    except ValueError as exc:
        mismatches.append(
            _make_mismatch(
                doc=api_doc_name,
                check="reason_example",
                key="reason",
                expected="reason[] JSON example with component and weight",
                actual=None,
                message=str(exc),
            )
        )
    else:
        mismatches.extend(
            _compare_subset(
                doc=api_doc_name,
                check="reason_example",
                expected=weights,
                actual=reason_weights,
            )
        )

    confidence_doc_weights = _extract_confidence_weights(scoring_doc)
    if confidence_doc_weights is not None:
        mismatches.extend(
            _compare_exact(
                doc=scoring_doc_name,
                check="confidence_weights",
                expected=confidence_weights,
                actual=confidence_doc_weights,
            )
        )

    allowlist = _load_allowlist(allowlist_path)
    remaining, warnings = _partition_mismatches(mismatches, allowlist)
    return CheckResult(
        mismatches=sorted(remaining),
        warnings=warnings,
        exit_code=1 if remaining else 0,
    )


def _format_value(value: Any) -> str:
    if value is None:
        return "None"
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True)
    return str(value)


def _render_result(result: CheckResult) -> str:
    lines: list[str] = []
    for mismatch in result.mismatches:
        lines.append(
            "ERROR "
            f"doc={mismatch.doc} check={mismatch.check} key={mismatch.key} "
            f"expected={_format_value(mismatch.expected)} actual={_format_value(mismatch.actual)} "
            f"message={mismatch.message}"
        )
    for warning in result.warnings:
        lines.append(
            "WARNING "
            f"doc={warning.doc} check={warning.check} key={warning.key} message={warning.message}"
        )
    if result.mismatches:
        lines.append(f"docs sync check failed: {len(result.mismatches)} unallowlisted mismatches")
    elif result.warnings:
        pending = sum(1 for warning in result.warnings if warning.kind == "allowlisted")
        stale = sum(1 for warning in result.warnings if warning.kind == "stale")
        summary = f"{pending} known diffs pending ratification (S12/T3)"
        if stale:
            summary += f"; {stale} stale allowlist entries"
        lines.append(summary)
    else:
        lines.append("docs in sync with config/scoring.yaml")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    config_dir = DEFAULT_CONFIG_DIR
    docs_dir = DEFAULT_DOCS_DIR
    allowlist_path = DEFAULT_ALLOWLIST_PATH

    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg == "--config-dir":
            index += 1
            config_dir = Path(argv[index])
        elif arg == "--docs-dir":
            index += 1
            docs_dir = Path(argv[index])
        elif arg == "--allowlist":
            index += 1
            allowlist_path = Path(argv[index])
        else:
            raise SystemExit(f"unknown argument: {arg}")
        index += 1

    result = run_check(config_dir, docs_dir, allowlist_path)
    print(_render_result(result))
    return result.exit_code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
