"""Sigma rule-corpus feed adapter (ADR-0013, #61, design spike for issue #61).

Stores Sigma rule **text and metadata as knowledge**, never compiles or
evaluates a rule. Full-replace: `sigma_rule_corpus` is deleted and
repopulated in one writer transaction, pinned to a `corpus_version`
resolved from config (mirrors `attack_version` in `feeds/adapters/attack.py`).

Parsing never invokes a Sigma backend. Validation reuses the exact
round-trip discipline `rules/lint.py:lint_sigma` already performs on
*generated* Sigma drafts (`yaml.safe_load` -> `yaml.safe_dump` ->
`yaml.safe_load`, unchanged) as an *ingest* gate: a rule that fails this
check is quarantined via `insert_quarantine`, never inserted.
"""

from __future__ import annotations

import io
import json
import tarfile
from datetime import timedelta
from typing import Any

import yaml

from azazel_knowledge.core.clock import to_rfc3339
from azazel_knowledge.feeds.base import FeedAdapter, FeedError
from azazel_knowledge.rules.lint import lint_sigma

_SIGMA_SUFFIXES = (".yml", ".yaml")
_DEFAULT_LICENSE = "DRL 1.1"


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


class SigmaCorpusAdapter(FeedAdapter):
    full_replace = True

    def parse(self, raw: bytes) -> list[dict[str, Any]]:
        corpus_version = self.config.get("corpus_version")
        if not corpus_version:
            raise FeedError(f"{self.feed_id}: missing corpus_version")
        source_url = self.config.get("source_url", "")
        default_license = self.config.get("license") or _DEFAULT_LICENSE
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
        for name, data in _iter_tar_members(raw, _SIGMA_SUFFIXES):
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError as exc:
                quarantine("decode_error", f"{name}: {exc}")
                continue

            if not lint_sigma(text):
                quarantine("malformed_yaml", f"{name}: failed round-trip validation")
                continue

            loaded = yaml.safe_load(text)
            rule_uid = loaded.get("id")
            title = loaded.get("title")
            if not rule_uid or not title:
                quarantine("missing_required_field", f"{name}: missing id/title")
                continue

            tags = [str(t) for t in (loaded.get("tags") or [])]
            attack_refs = sorted({t for t in tags if t.startswith("attack.")})
            license_ = str(loaded.get("license") or default_license)
            if allowed_licenses is not None and license_ not in allowed_licenses:
                quarantine("disallowed_license", f"{name}: license={license_!r}")
                continue

            rows.append(
                {
                    "rule_uid": str(rule_uid),
                    "title": str(title),
                    "raw_yaml": text,
                    "tags": tags,
                    "attack_refs": attack_refs,
                    "log_source": loaded.get("logsource") or {},
                    "level": loaded.get("level"),
                    "author": loaded.get("author"),
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
            conn.execute("DELETE FROM sigma_rule_corpus")
            conn.executemany(
                "INSERT INTO sigma_rule_corpus (rule_uid, title, raw_yaml, tags, attack_refs, "
                "log_source, level, author, license, source_url, corpus_version, feed_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        row["rule_uid"],
                        row["title"],
                        row["raw_yaml"],
                        json.dumps(row["tags"]),
                        json.dumps(row["attack_refs"]),
                        json.dumps(row["log_source"], sort_keys=True),
                        row["level"],
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
