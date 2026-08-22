"""Sigma/YARA rule-corpus adapter tests (ADR-0013, #61).

Fixtures are built in-test with stdlib `tarfile` into an in-memory buffer
rather than committed as binary tar files (per ADR guidance) -- both
adapters' `fetch_bytes` are wired directly to the resulting bytes.
"""

from __future__ import annotations

import io
import json
import tarfile
from datetime import datetime, timezone
from typing import Any

import pytest

from azazel_knowledge.core.clock import FixedClock
from azazel_knowledge.feeds.adapters.sigma_corpus import SigmaCorpusAdapter
from azazel_knowledge.feeds.adapters.yara_corpus import YaraCorpusAdapter
from azazel_knowledge.feeds.base import FeedError

from _feeds_support import make_intel_writer, make_local_writer

NOW = datetime(2026, 8, 21, 0, 0, 0, tzinfo=timezone.utc)

VALID_SIGMA_RULE = """\
title: Suspicious PowerShell Encoded Command
id: 5f2eb852-9c39-4c9b-9a0a-111111111111
status: stable
description: Detects suspicious powershell encoded command usage
author: Test Author
date: 2026/01/01
level: high
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: '-enc'
  condition: selection
tags:
  - attack.t1059.001
  - attack.execution
license: DRL 1.1
"""

VALID_SIGMA_RULE_2 = """\
title: Suspicious Rundll32 Usage
id: 5f2eb852-9c39-4c9b-9a0a-222222222222
status: stable
author: Test Author
level: medium
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\rundll32.exe'
  condition: selection
tags:
  - attack.t1218.011
license: DRL 1.1
"""

MALFORMED_SIGMA_RULE = "this is not a sigma mapping, just a bare scalar string\n"

DISALLOWED_LICENSE_SIGMA_RULE = """\
title: Restricted Rule
id: 5f2eb852-9c39-4c9b-9a0a-333333333333
level: low
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: '\\cmd.exe'
  condition: selection
tags:
  - attack.t1059
license: Commercial-NoRedistribute
"""

VALID_YARA_RULE = """\
rule Example_Malware_Dropper : malware dropper
{
    meta:
        author = "Test Author"
        license = "CC0-1.0"
        description = "Example dropper detection"
        attack_technique = "attack.t1105"

    strings:
        $s1 = "malicious_marker_one"
        $s2 = "malicious_marker_two"
        $hex1 = { 6A 40 68 00 30 00 00 6A 14 8D 91 }

    condition:
        all of them
}
"""

DISALLOWED_LICENSE_YARA_RULE = """\
rule Restricted_Rule
{
    meta:
        author = "Vendor"
        license = "Commercial-NoRedistribute"

    strings:
        $a = "foo"

    condition:
        $a
}
"""

UNBALANCED_YARA_RULE = """\
rule Broken_Rule
{
    meta:
        author = "Nobody"
    strings:
        $a = "foo"
    condition:
        $a
"""


def _build_tar(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name in sorted(files):
            data = files[name].encode("utf-8")
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mtime = 0
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


SIGMA_TAR = _build_tar(
    {
        "sigma-1.0.0/rules/windows/proc_creation_powershell_encoded.yml": VALID_SIGMA_RULE,
        "sigma-1.0.0/rules/windows/proc_creation_rundll32.yml": VALID_SIGMA_RULE_2,
        "sigma-1.0.0/rules/windows/proc_creation_malformed.yml": MALFORMED_SIGMA_RULE,
        "sigma-1.0.0/rules/windows/proc_creation_restricted.yml": DISALLOWED_LICENSE_SIGMA_RULE,
        "sigma-1.0.0/README.md": "not a rule file\n",
    }
)

SIGMA_TAR_V2 = _build_tar(
    {
        "sigma-2.0.0/rules/windows/proc_creation_rundll32.yml": VALID_SIGMA_RULE_2,
    }
)

YARA_TAR = _build_tar(
    {
        "signature-base-1.0/yara/dropper.yar": VALID_YARA_RULE,
        "signature-base-1.0/yara/restricted.yar": DISALLOWED_LICENSE_YARA_RULE,
        "signature-base-1.0/yara/broken.yar": UNBALANCED_YARA_RULE,
        "signature-base-1.0/README.md": "not a rule file\n",
    }
)

YARA_TAR_V2 = _build_tar(
    {
        "signature-base-2.0/yara/dropper.yar": VALID_YARA_RULE,
    }
)

SIGMA_CONFIG = {
    "corpus_version": "1.0.0",
    "license": "DRL 1.1",
    "allowed_licenses": ["DRL 1.1"],
    "source_url": "https://example.invalid/sigmahq/sigma/releases/tag/r1.0.0",
}

YARA_CONFIG = {
    "corpus_version": "1.0",
    "license": "CC0-1.0",
    "allowed_licenses": ["CC0-1.0"],
    "source_url": "https://example.invalid/neo23x0/signature-base/releases/tag/v1.0",
}


def _make_sigma_adapter(tmp_path, tar_bytes: bytes = SIGMA_TAR, config: dict | None = None, with_local=True):
    intel = make_intel_writer(tmp_path)
    local = make_local_writer(tmp_path) if with_local else None
    return SigmaCorpusAdapter(
        "sigma_corpus",
        dict(config or SIGMA_CONFIG),
        intel,
        local_writer=local,
        clock=FixedClock(NOW),
        fetch_bytes=lambda: tar_bytes,
    )


def _make_yara_adapter(tmp_path, tar_bytes: bytes = YARA_TAR, config: dict | None = None, with_local=True):
    intel = make_intel_writer(tmp_path)
    local = make_local_writer(tmp_path) if with_local else None
    return YaraCorpusAdapter(
        "yara_corpus",
        dict(config or YARA_CONFIG),
        intel,
        local_writer=local,
        clock=FixedClock(NOW),
        fetch_bytes=lambda: tar_bytes,
    )


def _read_sigma_rows(adapter: SigmaCorpusAdapter) -> list[tuple]:
    def query(conn: Any):
        return conn.execute(
            "SELECT rule_uid, title, tags, attack_refs, license, source_url, corpus_version "
            "FROM sigma_rule_corpus ORDER BY rule_uid"
        ).fetchall()

    return adapter._exec_intel(query)


def _read_yara_rows(adapter: YaraCorpusAdapter) -> list[tuple]:
    def query(conn: Any):
        return conn.execute(
            "SELECT rule_name, tags, attack_refs, meta, condition_summary, license, "
            "source_url, corpus_version FROM yara_rule_corpus ORDER BY rule_name"
        ).fetchall()

    return adapter._exec_intel(query)


def _read_quarantine(adapter) -> list[tuple]:
    def query(conn: Any):
        return conn.execute(
            "SELECT feed_id, reason, detail FROM feed_quarantine ORDER BY reason"
        ).fetchall()

    return adapter._exec_local(query)


# ---- Sigma -----------------------------------------------------------------


def test_sigma_corpus_populates_expected_rows(tmp_path):
    adapter = _make_sigma_adapter(tmp_path)
    outcome = adapter.run()
    assert outcome.status == "applied"
    assert outcome.items_applied == 2  # malformed + disallowed-license rules excluded

    rows = _read_sigma_rows(adapter)
    uids = [r[0] for r in rows]
    assert "5f2eb852-9c39-4c9b-9a0a-111111111111" in uids
    assert "5f2eb852-9c39-4c9b-9a0a-222222222222" in uids
    assert "5f2eb852-9c39-4c9b-9a0a-333333333333" not in uids  # disallowed license

    by_uid = {r[0]: r for r in rows}
    row = by_uid["5f2eb852-9c39-4c9b-9a0a-111111111111"]
    _, title, tags_json, attack_refs_json, license_, source_url, corpus_version = row
    assert title == "Suspicious PowerShell Encoded Command"
    assert json.loads(tags_json) == ["attack.t1059.001", "attack.execution"]
    assert json.loads(attack_refs_json) == ["attack.execution", "attack.t1059.001"]
    assert license_ == "DRL 1.1"
    assert source_url == SIGMA_CONFIG["source_url"]
    assert corpus_version == "1.0.0"


def test_sigma_corpus_full_replace_swaps_corpus_version(tmp_path):
    adapter = _make_sigma_adapter(tmp_path)
    adapter.run()

    adapter._fetch_bytes = lambda: SIGMA_TAR_V2
    adapter.config = {**SIGMA_CONFIG, "corpus_version": "2.0.0"}
    outcome = adapter.run()
    assert outcome.status == "applied"

    rows = _read_sigma_rows(adapter)
    assert len(rows) == 1
    assert rows[0][0] == "5f2eb852-9c39-4c9b-9a0a-222222222222"
    assert rows[0][6] == "2.0.0"


def test_sigma_malformed_yaml_is_quarantined_not_inserted(tmp_path):
    adapter = _make_sigma_adapter(tmp_path)
    adapter.run()

    rows = _read_sigma_rows(adapter)
    uids = [r[0] for r in rows]
    assert len(uids) == 2  # the malformed rule never made it in

    quarantine = _read_quarantine(adapter)
    reasons = {r[1] for r in quarantine}
    assert "malformed_yaml" in reasons
    assert all(r[0] == "sigma_corpus" for r in quarantine)


def test_sigma_disallowed_license_is_skipped_and_quarantined(tmp_path):
    adapter = _make_sigma_adapter(tmp_path)
    adapter.run()

    rows = _read_sigma_rows(adapter)
    assert "5f2eb852-9c39-4c9b-9a0a-333333333333" not in [r[0] for r in rows]

    quarantine = _read_quarantine(adapter)
    reasons = {r[1] for r in quarantine}
    assert "disallowed_license" in reasons


def test_sigma_corpus_never_touches_ioc_tables(tmp_path):
    adapter = _make_sigma_adapter(tmp_path)
    adapter.run()

    def query(conn: Any):
        return (
            conn.execute("SELECT COUNT(*) FROM ioc").fetchone()[0],
            conn.execute("SELECT COUNT(*) FROM ioc_source").fetchone()[0],
        )

    assert adapter._exec_intel(query) == (0, 0)


def test_sigma_corpus_deterministic_across_runs(tmp_path):
    dir_a, dir_b = tmp_path / "a", tmp_path / "b"
    dir_a.mkdir()
    dir_b.mkdir()

    adapter_a = _make_sigma_adapter(dir_a)
    adapter_a.run()
    rows_a = _read_sigma_rows(adapter_a)

    adapter_b = _make_sigma_adapter(dir_b)
    adapter_b.run()
    rows_b = _read_sigma_rows(adapter_b)

    assert rows_a == rows_b


def test_sigma_corpus_missing_corpus_version_is_an_error(tmp_path):
    adapter = _make_sigma_adapter(tmp_path, config={**SIGMA_CONFIG, "corpus_version": None})
    with pytest.raises(FeedError):
        adapter.run()


# ---- YARA -------------------------------------------------------------------


def test_yara_corpus_populates_expected_rows(tmp_path):
    adapter = _make_yara_adapter(tmp_path)
    outcome = adapter.run()
    assert outcome.status == "applied"
    assert outcome.items_applied == 1  # restricted-license + unbalanced rules excluded

    rows = _read_yara_rows(adapter)
    assert len(rows) == 1
    rule_name, tags_json, attack_refs_json, meta_json, condition_summary, license_, source_url, corpus_version = rows[0]
    assert rule_name == "Example_Malware_Dropper"
    assert json.loads(tags_json) == ["malware", "dropper"]
    assert json.loads(attack_refs_json) == ["ATTACK.T1105"] or json.loads(attack_refs_json) == ["attack.t1105"]
    meta = json.loads(meta_json)
    assert meta["author"] == "Test Author"
    assert meta["license"] == "CC0-1.0"
    assert license_ == "CC0-1.0"
    assert source_url == YARA_CONFIG["source_url"]
    assert corpus_version == "1.0"
    assert isinstance(condition_summary, str)
    assert "string definition" in condition_summary
    assert "all of them" in condition_summary


def test_yara_corpus_full_replace_swaps_corpus_version(tmp_path):
    adapter = _make_yara_adapter(tmp_path)
    adapter.run()

    adapter._fetch_bytes = lambda: YARA_TAR_V2
    adapter.config = {**YARA_CONFIG, "corpus_version": "2.0"}
    outcome = adapter.run()
    assert outcome.status == "applied"

    rows = _read_yara_rows(adapter)
    assert len(rows) == 1
    assert rows[0][7] == "2.0"


def test_yara_disallowed_license_is_skipped_and_quarantined(tmp_path):
    adapter = _make_yara_adapter(tmp_path)
    adapter.run()

    rows = _read_yara_rows(adapter)
    assert "Restricted_Rule" not in [r[0] for r in rows]

    quarantine = _read_quarantine(adapter)
    reasons = {r[1] for r in quarantine}
    assert "disallowed_license" in reasons
    assert all(r[0] == "yara_corpus" for r in quarantine)


def test_yara_unbalanced_rule_is_quarantined_not_inserted(tmp_path):
    adapter = _make_yara_adapter(tmp_path)
    adapter.run()

    rows = _read_yara_rows(adapter)
    assert "Broken_Rule" not in [r[0] for r in rows]

    quarantine = _read_quarantine(adapter)
    reasons = {r[1] for r in quarantine}
    assert "unparseable_yara_rule" in reasons


def test_yara_corpus_never_touches_ioc_tables(tmp_path):
    adapter = _make_yara_adapter(tmp_path)
    adapter.run()

    def query(conn: Any):
        return (
            conn.execute("SELECT COUNT(*) FROM ioc").fetchone()[0],
            conn.execute("SELECT COUNT(*) FROM ioc_source").fetchone()[0],
        )

    assert adapter._exec_intel(query) == (0, 0)


def test_yara_corpus_deterministic_across_runs(tmp_path):
    dir_a, dir_b = tmp_path / "a", tmp_path / "b"
    dir_a.mkdir()
    dir_b.mkdir()

    adapter_a = _make_yara_adapter(dir_a)
    adapter_a.run()
    rows_a = _read_yara_rows(adapter_a)

    adapter_b = _make_yara_adapter(dir_b)
    adapter_b.run()
    rows_b = _read_yara_rows(adapter_b)

    assert rows_a == rows_b


def test_yara_corpus_missing_corpus_version_is_an_error(tmp_path):
    adapter = _make_yara_adapter(tmp_path, config={**YARA_CONFIG, "corpus_version": None})
    with pytest.raises(FeedError):
        adapter.run()
