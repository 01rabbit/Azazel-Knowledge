from __future__ import annotations

import json
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from azazel_knowledge.audit.logger import (
    GENESIS_HASH,
    AuditChain,
    AuditUnavailable,
    MerkleAnchor,
    verify_anchors,
    verify_chain,
)
from azazel_knowledge.security.redact import SecretRegistry


def _identity(text: str) -> str:
    return text


def test_append_creates_chained_lines(tmp_path: Path):
    chain = AuditChain(tmp_path / "stream", "proc1", "boot1", _identity)
    line0 = chain.append({"kind": "context", "n": 1})
    line1 = chain.append({"kind": "context", "n": 2})
    chain.flush()
    assert line0["prev"] == GENESIS_HASH
    assert line1["prev"] == line0["hash"]
    assert line0["seq"] == 0
    assert line1["seq"] == 1


def test_verify_chain_ok_after_appends(tmp_path: Path):
    chain = AuditChain(tmp_path / "stream", "proc1", "boot1", _identity)
    for i in range(10):
        chain.append({"i": i})
    chain.flush()
    result = verify_chain(chain.path)
    assert result.ok
    assert result.lines == 10


def test_verify_chain_empty_file_ok(tmp_path: Path):
    result = verify_chain(tmp_path / "does-not-exist.jsonl")
    assert result.ok
    assert result.lines == 0


def test_tampered_middle_line_breaks_verify(tmp_path: Path):
    chain = AuditChain(tmp_path / "stream", "proc1", "boot1", _identity)
    for i in range(5):
        chain.append({"i": i})
    chain.flush()

    lines = chain.path.read_text().splitlines()
    assert len(lines) == 5
    middle = json.loads(lines[2])
    middle["event"]["i"] = 999
    lines[2] = json.dumps(middle, sort_keys=True, separators=(",", ":"))
    chain.path.write_text("\n".join(lines) + "\n")

    result = verify_chain(chain.path)
    assert not result.ok
    assert result.bad_seq == 2


def test_tampered_hash_breaks_verify(tmp_path: Path):
    chain = AuditChain(tmp_path / "stream", "proc1", "boot1", _identity)
    for i in range(3):
        chain.append({"i": i})
    chain.flush()

    lines = chain.path.read_text().splitlines()
    first = json.loads(lines[0])
    first["hash"] = "f" * 64
    lines[0] = json.dumps(first, sort_keys=True, separators=(",", ":"))
    chain.path.write_text("\n".join(lines) + "\n")

    result = verify_chain(chain.path)
    assert not result.ok


def test_chain_applies_redaction_before_persisting(tmp_path: Path):
    registry = SecretRegistry()
    chain = AuditChain(tmp_path / "stream", "proc1", "boot1", registry.redact)
    chain.append({"note": "token azcti_key01_supersecretvalue leaked"})
    chain.flush()
    text = chain.path.read_text()
    assert "azcti_key01_supersecretvalue" not in text
    assert "[REDACTED]" in text


def test_append_failure_raises_audit_unavailable_and_marks_unhealthy(tmp_path: Path):
    chain = AuditChain(tmp_path / "stream", "proc1", "boot1", _identity)

    class _FailingFile:
        def write(self, _text: str) -> None:
            raise OSError("disk full")

        def flush(self) -> None:
            pass

        def fileno(self) -> int:
            return 0

        def close(self) -> None:
            pass

    chain._fh = _FailingFile()
    assert chain.healthy
    with pytest.raises(AuditUnavailable):
        chain.append({"x": 1})
    assert not chain.healthy


def test_constructor_failure_raises_audit_unavailable(tmp_path: Path):
    blocked_path = tmp_path / "blocked"
    blocked_path.write_text("this is a file, not a directory")
    with pytest.raises(AuditUnavailable):
        AuditChain(blocked_path, "proc1", "boot1", _identity)


def test_reopen_resumes_seq_and_prev_hash(tmp_path: Path):
    stream_dir = tmp_path / "stream"
    chain = AuditChain(stream_dir, "proc1", "boot1", _identity)
    chain.append({"i": 0})
    chain.append({"i": 1})
    chain.flush()
    chain.close()

    chain2 = AuditChain(stream_dir, "proc1", "boot1", _identity)
    line = chain2.append({"i": 2})
    chain2.flush()
    assert line["seq"] == 2
    result = verify_chain(chain2.path)
    assert result.ok
    assert result.lines == 3


def _write_signing_key(path: Path) -> SigningKey:
    key = SigningKey.generate()
    path.write_bytes(bytes(key))
    return key


def test_merkle_anchor_sign_and_verify_roundtrip(tmp_path: Path):
    chains_dir = tmp_path / "chains"
    anchor_path = tmp_path / "anchors.jsonl"
    key_path = tmp_path / "node_signing_key"
    signing_key = _write_signing_key(key_path)

    chain_a = AuditChain(chains_dir, "procA", "bootX", _identity)
    chain_a.append({"e": 1})
    chain_a.flush()

    chain_b = AuditChain(chains_dir, "procB", "bootX", _identity)
    chain_b.append({"e": 2})
    chain_b.append({"e": 3})
    chain_b.flush()

    anchor_mgr = MerkleAnchor(chains_dir, anchor_path, signing_key)
    record = anchor_mgr.anchor()
    assert "merkle_root" in record
    assert len(record["heads"]) == 2

    assert verify_anchors(anchor_path, chains_dir, signing_key.verify_key)


def test_merkle_anchor_verify_fails_on_tampered_head(tmp_path: Path):
    chains_dir = tmp_path / "chains"
    anchor_path = tmp_path / "anchors.jsonl"
    key_path = tmp_path / "node_signing_key"
    signing_key = _write_signing_key(key_path)

    chain_a = AuditChain(chains_dir, "procA", "bootX", _identity)
    chain_a.append({"e": 1})
    chain_a.flush()

    anchor_mgr = MerkleAnchor(chains_dir, anchor_path, signing_key)
    anchor_mgr.anchor()

    lines = anchor_path.read_text().splitlines()
    record = json.loads(lines[0])
    for name in record["heads"]:
        record["heads"][name] = "0" * 64
    anchor_path.write_text(json.dumps(record) + "\n")

    assert not verify_anchors(anchor_path, chains_dir, signing_key.verify_key)


def test_merkle_anchor_verify_fails_on_wrong_key(tmp_path: Path):
    chains_dir = tmp_path / "chains"
    anchor_path = tmp_path / "anchors.jsonl"
    key_path = tmp_path / "node_signing_key"
    signing_key = _write_signing_key(key_path)
    other_key = SigningKey.generate()

    chain_a = AuditChain(chains_dir, "procA", "bootX", _identity)
    chain_a.append({"e": 1})
    chain_a.flush()

    anchor_mgr = MerkleAnchor(chains_dir, anchor_path, signing_key)
    anchor_mgr.anchor()

    assert not verify_anchors(anchor_path, chains_dir, other_key.verify_key)


def test_merkle_anchor_due_on_max_entries():
    anchor_mgr = MerkleAnchor.__new__(MerkleAnchor)
    anchor_mgr.max_entries = 5
    anchor_mgr.interval_s = 3600.0
    import time

    anchor_mgr._entries = 0
    anchor_mgr._last_time = time.monotonic()
    anchor_mgr.record_entries(5)
    assert anchor_mgr.due()
