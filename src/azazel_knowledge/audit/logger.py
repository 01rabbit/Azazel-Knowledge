from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

GENESIS_HASH = "0" * 64
FLUSH_MAX_LINES = 500
FLUSH_MAX_INTERVAL_S = 0.2

Redactor = Callable[[str], str]


class AuditUnavailable(Exception):
    pass


def _canonical_json(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _tail_line(path: Path) -> dict | None:
    if not path.exists():
        return None
    last: dict | None = None
    with path.open("r", encoding="utf-8") as fh:
        for raw in fh:
            raw = raw.strip()
            if not raw:
                continue
            try:
                last = json.loads(raw)
            except json.JSONDecodeError:
                continue
    return last


class AuditChain:
    def __init__(self, stream_dir: str | Path, proc_id: str, boot_id: str, redactor: Redactor) -> None:
        self.stream_dir = Path(stream_dir)
        self.proc_id = proc_id
        self.boot_id = boot_id
        self._redactor = redactor
        self.healthy = True
        self._lock = threading.Lock()
        self._pending = 0
        self._last_flush = time.monotonic()
        self.path = self.stream_dir / f"{proc_id}.{boot_id}.jsonl"
        try:
            self.stream_dir.mkdir(parents=True, exist_ok=True)
            last = _tail_line(self.path)
            if last is not None:
                self._seq = int(last["seq"]) + 1
                self._prev_hash = str(last["hash"])
            else:
                self._seq = 0
                self._prev_hash = GENESIS_HASH
            self._fh = open(self.path, "a", encoding="utf-8")
        except OSError as exc:
            self.healthy = False
            raise AuditUnavailable(str(exc)) from exc

    def append(self, event: dict) -> dict:
        with self._lock:
            try:
                redacted_text = self._redactor(_canonical_json(event).decode("utf-8"))
                redacted_event = json.loads(redacted_text)
                payload = {
                    "seq": self._seq,
                    "ts": _now_iso(),
                    "proc_id": self.proc_id,
                    "boot_id": self.boot_id,
                    "prev": self._prev_hash,
                    "event": redacted_event,
                }
                digest = hashlib.sha256(self._prev_hash.encode("ascii") + _canonical_json(payload)).hexdigest()
                line = {**payload, "hash": digest}
                self._fh.write(_canonical_json(line).decode("utf-8") + "\n")
                self._pending += 1
                self._seq += 1
                self._prev_hash = digest
                now = time.monotonic()
                if self._pending >= FLUSH_MAX_LINES or (now - self._last_flush) >= FLUSH_MAX_INTERVAL_S:
                    self._flush_locked()
                return line
            except OSError as exc:
                self.healthy = False
                raise AuditUnavailable(str(exc)) from exc

    def _flush_locked(self) -> None:
        self._fh.flush()
        os.fsync(self._fh.fileno())
        self._pending = 0
        self._last_flush = time.monotonic()

    def flush(self) -> None:
        with self._lock:
            try:
                self._flush_locked()
            except OSError as exc:
                self.healthy = False
                raise AuditUnavailable(str(exc)) from exc

    def close(self) -> None:
        with self._lock:
            if self._fh is not None:
                try:
                    self._flush_locked()
                finally:
                    self._fh.close()
                    self._fh = None


@dataclass(frozen=True)
class ChainVerification:
    ok: bool
    lines: int
    error: str | None = None
    bad_seq: int | None = None


def verify_chain(path: str | Path) -> ChainVerification:
    p = Path(path)
    if not p.exists():
        return ChainVerification(ok=True, lines=0)
    prev = GENESIS_HASH
    count = 0
    with p.open("r", encoding="utf-8") as fh:
        for line_no, raw in enumerate(fh):
            raw = raw.strip()
            if not raw:
                continue
            try:
                line = json.loads(raw)
            except json.JSONDecodeError as exc:
                return ChainVerification(ok=False, lines=count, error=str(exc), bad_seq=line_no)
            stored_hash = line.get("hash")
            payload = {k: v for k, v in line.items() if k != "hash"}
            if payload.get("prev") != prev:
                return ChainVerification(
                    ok=False, lines=count, error="prev mismatch", bad_seq=payload.get("seq", line_no)
                )
            expected_hash = hashlib.sha256(prev.encode("ascii") + _canonical_json(payload)).hexdigest()
            if expected_hash != stored_hash:
                return ChainVerification(
                    ok=False, lines=count, error="hash mismatch", bad_seq=payload.get("seq", line_no)
                )
            prev = stored_hash
            count += 1
    return ChainVerification(ok=True, lines=count)


def _read_chain_heads(chains_dir: str | Path) -> dict[str, str]:
    base = Path(chains_dir)
    heads: dict[str, str] = {}
    if not base.exists():
        return heads
    for path in sorted(base.rglob("*.jsonl")):
        last = _tail_line(path)
        if last is not None and "hash" in last:
            heads[str(path.relative_to(base))] = last["hash"]
    return heads


def _merkle_root(heads: dict[str, str]) -> str:
    if not heads:
        return hashlib.sha256(b"").hexdigest()
    leaves = [hashlib.sha256(f"{name}:{h}".encode("utf-8")).digest() for name, h in sorted(heads.items())]
    level = leaves
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else level[i]
            nxt.append(hashlib.sha256(left + right).digest())
        level = nxt
    return level[0].hex()


def load_signing_key(path: str | Path) -> SigningKey:
    return SigningKey(Path(path).read_bytes())


def load_verify_key(path: str | Path) -> VerifyKey:
    return VerifyKey(Path(path).read_bytes())


class MerkleAnchor:
    def __init__(
        self,
        chains_dir: str | Path,
        anchor_path: str | Path,
        signing_key: SigningKey,
        interval_s: float = 3600.0,
        max_entries: int = 500,
    ) -> None:
        self.chains_dir = Path(chains_dir)
        self.anchor_path = Path(anchor_path)
        self.signing_key = signing_key
        self.interval_s = interval_s
        self.max_entries = max_entries
        self._entries = 0
        self._last_time = time.monotonic()

    def record_entries(self, n: int = 1) -> None:
        self._entries += n

    def due(self) -> bool:
        return self._entries >= self.max_entries or (time.monotonic() - self._last_time) >= self.interval_s

    def anchor(self) -> dict:
        heads = _read_chain_heads(self.chains_dir)
        root = _merkle_root(heads)
        signature = self.signing_key.sign(bytes.fromhex(root)).signature.hex()
        record = {
            "ts": _now_iso(),
            "heads": heads,
            "merkle_root": root,
            "signature": signature,
            "verify_key": self.signing_key.verify_key.encode().hex(),
        }
        self.anchor_path.parent.mkdir(parents=True, exist_ok=True)
        with self.anchor_path.open("a", encoding="utf-8") as fh:
            fh.write(_canonical_json(record).decode("utf-8") + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        self._entries = 0
        self._last_time = time.monotonic()
        return record

    def maybe_anchor(self) -> dict | None:
        if self.due():
            return self.anchor()
        return None


def _hash_in_chain(path: Path, target_hash: str) -> bool:
    if not path.exists():
        return False
    with path.open("r", encoding="utf-8") as fh:
        for raw in fh:
            raw = raw.strip()
            if not raw:
                continue
            try:
                line = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if line.get("hash") == target_hash:
                return True
    return False


def verify_anchors(anchor_path: str | Path, chains_dir: str | Path, verify_key: VerifyKey) -> bool:
    p = Path(anchor_path)
    if not p.exists():
        return True
    base = Path(chains_dir)
    with p.open("r", encoding="utf-8") as fh:
        for raw in fh:
            raw = raw.strip()
            if not raw:
                continue
            record = json.loads(raw)
            root = record.get("merkle_root", "")
            signature = record.get("signature", "")
            heads = record.get("heads", {})
            try:
                verify_key.verify(bytes.fromhex(root), bytes.fromhex(signature))
            except (BadSignatureError, ValueError):
                return False
            if _merkle_root(heads) != root:
                return False
            for name, head_hash in heads.items():
                if not _hash_in_chain(base / name, head_hash):
                    return False
    return True
