"""YARA rule-corpus feed adapter (ADR-0013, #61, design spike for issue #61).

Stores YARA rule **text and metadata as knowledge**. This module has no
dependency on a compiled YARA scan engine and never calls anything that
would treat rule content as executable. Full-replace: `yara_rule_corpus`
is deleted and repopulated in one writer transaction, pinned to a
`corpus_version` resolved from config.

YARA source is not YAML, so metadata is extracted with a small stdlib-`re`
grammar walk over `rule NAME : tag1 tag2 { meta: key = "value" ... }` --
a metadata-only extractor, not a YARA grammar parser and never a condition
evaluator. Patterns below are plain strings passed straight to module-level
`re.search`/`re.finditer`/`re.findall` -- no precompiled pattern objects, no
byte-pattern evaluation. `condition_summary` is a human-readable description
built by counting `$`-prefixed string definitions and pattern-matching a
couple of common idioms (hash equality, "all of them"); it is never a
re-parseable AST and is never evaluated.
"""

from __future__ import annotations

import io
import json
import re
import tarfile
from datetime import timedelta
from typing import Any

from azazel_knowledge.core.clock import to_rfc3339
from azazel_knowledge.feeds.base import FeedAdapter, FeedError

_YARA_SUFFIXES = (".yar", ".yara")

_RULE_HEADER_PATTERN = r"(?m)^[ \t]*(?:(?:private|global)\s+)*rule\s+([A-Za-z_]\w*)\s*(?::\s*([^\{]+))?\{"
_META_SECTION_PATTERN = r"meta\s*:\s*(.*?)(?=\n\s*(?:strings|condition)\s*:|\Z)"
_STRINGS_SECTION_PATTERN = r"strings\s*:\s*(.*?)(?=\n\s*condition\s*:|\Z)"
_CONDITION_SECTION_PATTERN = r"condition\s*:\s*(.*)\Z"
_META_KV_PATTERN = r'(\w+)\s*=\s*"((?:[^"\\]|\\.)*)"'
_STRING_DEF_PATTERN = r"\$\w*\s*="
_ATTACK_ID_PATTERN = r"(?i)\bATTACK\.T\d{4}(?:\.\d{3})?\b|\bT\d{4}(?:\.\d{3})?\b"


def _iter_tar_members(raw: bytes, suffixes: tuple[str, ...]) -> list[tuple[str, bytes]]:
    """Read matching regular-file members out of a (possibly gzip'd) tar
    archive, sorted by member name for deterministic processing order."""
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as tar:
        members = sorted(
            (m for m in tar.getmembers() if m.isfile() and m.name.lower().endswith(suffixes)),
            key=lambda m: m.name,
        )
        out: list[tuple[str, bytes]] = []
        for member in members:
            fileobj = tar.extractfile(member)
            if fileobj is None:
                continue
            out.append((member.name, fileobj.read()))
        return out


def _find_matching_brace(text: str, open_pos: int) -> int | None:
    """Return the index of the `}` matching the `{` at `open_pos`, walking
    forward and ignoring braces inside double-quoted strings. Returns None
    if the archive text cannot be confidently split into a balanced block."""
    depth = 0
    i = open_pos
    in_string = False
    n = len(text)
    while i < n:
        ch = text[i]
        if in_string:
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            i += 1
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def _extract_meta(rule_body: str) -> dict[str, str]:
    section = re.search(_META_SECTION_PATTERN, rule_body, re.DOTALL)
    if not section:
        return {}
    meta_text = section.group(1)
    return {k: v.replace('\\"', '"') for k, v in re.findall(_META_KV_PATTERN, meta_text)}


def _condition_summary(rule_body: str) -> str:
    strings_section = re.search(_STRINGS_SECTION_PATTERN, rule_body, re.DOTALL)
    strings_text = strings_section.group(1) if strings_section else ""
    string_count = len(re.findall(_STRING_DEF_PATTERN, strings_text))

    condition_section = re.search(_CONDITION_SECTION_PATTERN, rule_body, re.DOTALL)
    condition_text = condition_section.group(1) if condition_section else ""
    # Drop the rule's own closing brace, which the condition pattern's
    # greedy tail otherwise swallows.
    condition_text = condition_text.rsplit("}", 1)[0]

    parts = [f"{string_count} string definition(s)"]
    if "hash." in condition_text:
        parts.append("hash condition")
    if "all of them" in condition_text:
        parts.append("all of them")
    return ", ".join(parts)


def _split_rule_blocks(text: str) -> list[tuple[str, list[str], str | None]]:
    """Split `text` into `(rule_name, tags, rule_body)` tuples. `rule_body`
    is None when the block's braces could not be confidently balanced --
    callers must quarantine, not insert, such an entry."""
    blocks: list[tuple[str, list[str], str | None]] = []
    for header in re.finditer(_RULE_HEADER_PATTERN, text):
        name = header.group(1)
        tag_blob = header.group(2) or ""
        tags = tag_blob.split()
        brace_start = header.end() - 1  # position of the opening '{'
        close_pos = _find_matching_brace(text, brace_start)
        if close_pos is None:
            blocks.append((name, tags, None))
            continue
        blocks.append((name, tags, text[header.start() : close_pos + 1]))
    return blocks


class YaraCorpusAdapter(FeedAdapter):
    full_replace = True

    def parse(self, raw: bytes) -> list[dict[str, Any]]:
        corpus_version = self.config.get("corpus_version")
        if not corpus_version:
            raise FeedError(f"{self.feed_id}: missing corpus_version")
        source_url = self.config.get("source_url", "")
        default_license = self.config.get("license", "")
        allowed_licenses = self.config.get("allowed_licenses")
        base_now = self.clock.query_as_of()
        seq = [0]

        def quarantine(reason: str, detail: str) -> None:
            # `feed_quarantine` is keyed on (feed_id, quarantined_at); a single
            # run can quarantine several rules at the identical `query_as_of`
            # tick, so a deterministic microsecond offset (derived from the
            # fixed clock reading, not a wall-clock read) keeps each entry's
            # key unique without breaking replay determinism.
            ts = to_rfc3339(base_now + timedelta(microseconds=seq[0]))
            seq[0] += 1
            self.insert_quarantine(ts, reason, detail)

        rows: list[dict[str, Any]] = []
        for name, data in _iter_tar_members(raw, _YARA_SUFFIXES):
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError as exc:
                quarantine("decode_error", f"{name}: {exc}")
                continue

            blocks = _split_rule_blocks(text)
            if not blocks:
                quarantine("unparseable_yara_rule", f"{name}: no rule block found")
                continue

            for rule_name, tags, rule_body in blocks:
                if rule_body is None:
                    quarantine("unparseable_yara_rule", f"{name}: {rule_name}: unbalanced rule block")
                    continue

                meta = _extract_meta(rule_body)
                license_ = meta.get("license") or default_license
                if allowed_licenses is not None and license_ not in allowed_licenses:
                    quarantine("disallowed_license", f"{name}: {rule_name}: license={license_!r}")
                    continue

                candidates = list(meta.values()) + tags
                attack_refs: set[str] = set()
                for candidate in candidates:
                    attack_refs.update(re.findall(_ATTACK_ID_PATTERN, candidate))

                rows.append(
                    {
                        "rule_name": rule_name,
                        "raw_text": rule_body,
                        "tags": tags,
                        "meta": meta,
                        "attack_refs": sorted(attack_refs),
                        "condition_summary": _condition_summary(rule_body),
                        "author": meta.get("author"),
                        "license": license_,
                        "source_url": source_url,
                        "corpus_version": str(corpus_version),
                    }
                )
        return rows

    def item_count(self, items: list[dict[str, Any]]) -> int:
        return len(items)

    def apply_batch(self, batch: list[dict[str, Any]]) -> int:
        def txn(conn: Any) -> int:
            conn.execute("DELETE FROM yara_rule_corpus")
            conn.executemany(
                "INSERT INTO yara_rule_corpus (rule_name, raw_text, tags, meta, attack_refs, "
                "condition_summary, author, license, source_url, corpus_version, feed_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        row["rule_name"],
                        row["raw_text"],
                        json.dumps(row["tags"]),
                        json.dumps(row["meta"], sort_keys=True),
                        json.dumps(row["attack_refs"]),
                        row["condition_summary"],
                        row["author"],
                        row["license"],
                        row["source_url"],
                        row["corpus_version"],
                        self.feed_id,
                    )
                    for row in batch
                ],
            )
            return len(batch)

        return self._exec_intel(txn)
