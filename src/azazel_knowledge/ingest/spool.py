"""Durable fire-and-forget ingest spool (design S2/S4, F-4).

Layout: ``<root>/<endpoint>/`` holds the **pending** batches -- a
``<batch_id>.jsonl`` payload plus a ``<batch_id>.client`` sidecar recording
which API client wrote it (needed for per-client quota accounting before
the drainer has produced a status file). Once the worker drains a batch,
all three files move to ``<root>/<endpoint>/drained/``, where the
``<batch_id>.status.json`` joins them and where retention (worker P3) later
collects them. Writes are staged to a ``.tmp`` file, fsynced, atomically
renamed, and the containing directory is then fsynced so a crash never
leaves a half-written batch visible to the drainer.

**Drained batches move out of the pending directory on purpose.** Every
accept charges a per-client quota scan of that directory, and retention
keeps drained batches for a week, so leaving them in place made an accept
O(batches accepted in the last 7 days): measured at 2.07 ms against an empty
directory and 232.92 ms against 5 000 drained batches, growing linearly
(ADR-0003, "Measurement (2026-09-19)"). With drained batches elsewhere the
scan is bounded by what the quota already bounds -- the bytes a client has
pending -- instead of by ingest history.

``batch_id`` is a sortable, ULID-like 30-hex-character token: 40 bits of
millisecond time followed by 80 bits of randomness, so batches list in
arrival order and collisions are practically impossible even under
concurrent writers.
"""

from __future__ import annotations

import json
import os
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

_TIME_BITS = 40
_RANDOM_BITS = 80
_TIME_MASK = (1 << _TIME_BITS) - 1

DEFAULT_QUOTA_BYTES = 64 * 1024 * 1024

#: Subdirectory of an endpoint that holds batches the worker has drained.
#: A batch is pending exactly while its payload sits in the endpoint
#: directory itself, so moving it here is what ends its pending life.
DRAINED_DIRNAME = "drained"


class QuotaExceeded(Exception):
    """Raised when a client's pending spooled bytes would exceed its quota.

    The API layer should translate this into a ``503`` response.
    """

    def __init__(
        self,
        *,
        endpoint: str,
        client_key_id: str,
        used_bytes: int,
        requested_bytes: int,
        quota_bytes: int,
    ) -> None:
        super().__init__(
            f"quota exceeded for client={client_key_id!r} endpoint={endpoint!r}: "
            f"{used_bytes} + {requested_bytes} > {quota_bytes}"
        )
        self.endpoint = endpoint
        self.client_key_id = client_key_id
        self.used_bytes = used_bytes
        self.requested_bytes = requested_bytes
        self.quota_bytes = quota_bytes


def new_batch_id(now: float | None = None) -> str:
    ts_ms = int((now if now is not None else time.time()) * 1000)
    time_part = ts_ms & _TIME_MASK
    random_part = secrets.randbits(_RANDOM_BITS)
    return f"{time_part:010x}{random_part:020x}"


@dataclass(frozen=True)
class PendingBatch:
    batch_id: str
    client_key_id: str
    path: Path


@dataclass
class BatchStatus:
    batch_id: str
    accepted: str
    line_count: int
    valid: int
    invalid: list[dict[str, Any]] = field(default_factory=list)
    drained: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "batch_id": self.batch_id,
            "accepted": self.accepted,
            "line_count": self.line_count,
            "valid": self.valid,
            "invalid": self.invalid,
            "drained": self.drained,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BatchStatus":
        return cls(
            batch_id=data["batch_id"],
            accepted=data["accepted"],
            line_count=int(data["line_count"]),
            valid=int(data["valid"]),
            invalid=list(data.get("invalid", [])),
            drained=bool(data.get("drained", False)),
        )


def _fsync_file(path: Path, payload: bytes) -> None:
    with open(path, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_move(src: Path, dst: Path) -> None:
    """Move a spool file between directories, durably.

    ``os.replace`` is atomic within a filesystem, and both directories are
    fsynced so the rename survives a crash. A missing source is not an error:
    the caller may be finishing a move a previous crash left half-done.
    """
    if not src.exists():
        return
    os.replace(src, dst)
    _fsync_dir(dst.parent)
    _fsync_dir(src.parent)


def _atomic_write(final_path: Path, payload: bytes) -> None:
    tmp_path = final_path.with_suffix(final_path.suffix + ".tmp")
    _fsync_file(tmp_path, payload)
    os.replace(tmp_path, final_path)
    _fsync_dir(final_path.parent)


class SpoolWriter:
    def __init__(self, root: Path | str, quota_bytes: int = DEFAULT_QUOTA_BYTES) -> None:
        self.root = Path(root)
        self.quota_bytes = quota_bytes

    def _endpoint_dir(self, endpoint: str) -> Path:
        return self.root / endpoint

    def _drained_dir(self, endpoint: str) -> Path:
        return self._endpoint_dir(endpoint) / DRAINED_DIRNAME

    def _client_path(self, endpoint: str, client_key_id: str) -> Path:
        return self._endpoint_dir(endpoint) / f"{client_key_id}.client"

    def _status_path(self, endpoint: str, batch_id: str) -> Path:
        return self._endpoint_dir(endpoint) / f"{batch_id}.status.json"

    def _client_of(self, endpoint_dir: Path, batch_id: str) -> str:
        client_path = endpoint_dir / f"{batch_id}.client"
        if client_path.is_file():
            return client_path.read_text(encoding="utf-8").strip()
        return ""

    def _read_status_at(self, path: Path) -> BatchStatus | None:
        if not path.is_file():
            return None
        return BatchStatus.from_dict(json.loads(path.read_text(encoding="utf-8")))

    def _pending_bytes_for_client(self, endpoint_dir: Path, client_key_id: str) -> int:
        total = 0
        for jsonl_path in endpoint_dir.glob("*.jsonl"):
            batch_id = jsonl_path.stem
            if self._client_of(endpoint_dir, batch_id) != client_key_id:
                continue
            status = self._read_status_at(endpoint_dir / f"{batch_id}.status.json")
            if status is not None and status.drained:
                continue
            total += jsonl_path.stat().st_size
        return total

    def write_batch(
        self, endpoint: str, client_key_id: str, raw_lines: Iterable[str]
    ) -> str:
        lines = list(raw_lines)
        payload = ("\n".join(lines) + "\n").encode("utf-8") if lines else b""
        endpoint_dir = self._endpoint_dir(endpoint)
        endpoint_dir.mkdir(parents=True, exist_ok=True)

        used = self._pending_bytes_for_client(endpoint_dir, client_key_id)
        if used + len(payload) > self.quota_bytes:
            raise QuotaExceeded(
                endpoint=endpoint,
                client_key_id=client_key_id,
                used_bytes=used,
                requested_bytes=len(payload),
                quota_bytes=self.quota_bytes,
            )

        batch_id = new_batch_id()
        final_path = endpoint_dir / f"{batch_id}.jsonl"
        _atomic_write(final_path, payload)
        _atomic_write(
            endpoint_dir / f"{batch_id}.client", client_key_id.encode("utf-8")
        )
        return batch_id

    def pending_batches(self, endpoint: str) -> list[PendingBatch]:
        endpoint_dir = self._endpoint_dir(endpoint)
        if not endpoint_dir.is_dir():
            return []
        out: list[PendingBatch] = []
        for jsonl_path in endpoint_dir.glob("*.jsonl"):
            batch_id = jsonl_path.stem
            status = self._read_status_at(endpoint_dir / f"{batch_id}.status.json")
            if status is not None and status.drained:
                continue
            out.append(
                PendingBatch(
                    batch_id=batch_id,
                    client_key_id=self._client_of(endpoint_dir, batch_id),
                    path=jsonl_path,
                )
            )
        return sorted(out, key=lambda b: b.batch_id)

    def write_status(self, endpoint: str, batch_id: str, status: BatchStatus) -> None:
        """Record a batch's outcome; a drained batch also leaves the pending set.

        The move happens **before** the status is written, because the payload's
        absence from the endpoint directory is what makes a batch non-pending.
        A crash between the two leaves a drained batch whose status reads as
        unknown -- an observability gap, not a correctness one, and strictly
        smaller than the window that already exists between the database commit
        and this call, in which the batch is still pending and would be
        replayed.
        """
        endpoint_dir = self._endpoint_dir(endpoint)
        endpoint_dir.mkdir(parents=True, exist_ok=True)
        payload = (json.dumps(status.to_dict(), sort_keys=True) + "\n").encode("utf-8")

        if not status.drained:
            _atomic_write(self._status_path(endpoint, batch_id), payload)
            return

        drained_dir = self._drained_dir(endpoint)
        drained_dir.mkdir(parents=True, exist_ok=True)
        for suffix in (".jsonl", ".client"):
            _atomic_move(
                endpoint_dir / f"{batch_id}{suffix}", drained_dir / f"{batch_id}{suffix}"
            )
        _atomic_write(drained_dir / f"{batch_id}.status.json", payload)

    def read_status(self, batch_id: str) -> BatchStatus | None:
        """Find a batch's status wherever it lives.

        A drained batch's status sits under ``<endpoint>/drained/``; a spool
        written before that layout, or a batch whose status was recorded
        without being drained, has it directly under ``<endpoint>/``. Both are
        searched so an upgrade does not make already-drained batches report
        as unknown.
        """
        if not self.root.is_dir():
            return None
        for pattern in (
            f"*/{DRAINED_DIRNAME}/{batch_id}.status.json",
            f"*/{batch_id}.status.json",
        ):
            for status_path in self.root.glob(pattern):
                return self._read_status_at(status_path)
        return None
