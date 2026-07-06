"""Bundle import: verify -> stage -> build/patch intel.db -> swap -> anchor.

Full import builds a brand-new `gen-<N+1>/intel.db` from the bundle's
JSONL table dumps and only then repoints `current`; on any failure
before that repoint, the new generation directory is removed and
`current` is left untouched (design S6: "Import is atomic"). Only the
final symlink swap and the `state.toml` update are live-writer actions;
building the new generation touches a file nothing else reads yet.

Differential import never builds a new generation: it applies per-table
upsert/delete deltas to the *live* generation through a writer
connection the caller already owns (e.g. the worker's single-writer
queue), one transaction per table batch.

Neither path ever opens, reads, or writes `local.db` -- bundles are
intel-tier only (F-1); `verify_bundle` already hard-aborts on any bundle
naming a local-tier table, and the assertions here are a second,
structural line of defense.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from azazel_cti.bundle import rollback_anchor
from azazel_cti.bundle.verify import VerifiedBundle, verify_bundle
from azazel_cti.db import generations
from azazel_cti.db.repository import apply_migrations

_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class BundleImportError(Exception):
    pass


@dataclass(frozen=True)
class ImportResult:
    bundle_version: int
    tables: dict[str, int]
    generation: int | None = None
    removed_generations: list[int] = field(default_factory=list)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _assert_not_local_db(path: Path) -> None:
    if path.name == "local.db" or "local.db" in path.parts:
        raise AssertionError(f"bundle importer must never touch local.db, got {path}")


def _validate_identifier(name: str) -> None:
    if not _IDENT_RE.match(name):
        raise BundleImportError(f"unsafe table identifier: {name!r}")


def _table_columns(conn: sqlite3.Connection, table: str) -> list[str]:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    if not rows:
        raise BundleImportError(f"unknown table {table!r} in target intel.db")
    return [row[1] for row in rows]


def _table_pk_columns(conn: sqlite3.Connection, table: str) -> list[str]:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    pk_rows = sorted((row for row in rows if row[5] > 0), key=lambda row: row[5])
    return [row[1] for row in pk_rows]


def _sha256_file(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _warm(intel_path: Path) -> None:
    try:
        fd = os.open(intel_path, os.O_RDONLY)
    except OSError:
        return
    try:
        fadvise = getattr(os, "posix_fadvise", None)
        will_need = getattr(os, "POSIX_FADV_WILLNEED", None)
        if fadvise is not None and will_need is not None:
            size = os.fstat(fd).st_size
            fadvise(fd, 0, size, will_need)
    except OSError:
        pass
    finally:
        os.close(fd)


def _read_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def _insert_full_table(conn: sqlite3.Connection, table: str, rows: list[dict]) -> int:
    _validate_identifier(table)
    _table_columns(conn, table)
    if not rows:
        return 0
    col_names = sorted(rows[0].keys())
    placeholders = ",".join("?" for _ in col_names)
    conn.executemany(
        f"INSERT INTO {table} ({','.join(col_names)}) VALUES ({placeholders})",
        [[row[c] for c in col_names] for row in rows],
    )
    return len(rows)


def import_full(
    bundle_path: str | Path,
    anchors_path: str | Path,
    state_path: str | Path,
    data_db_dir: str | Path,
    *,
    staging_dir: str | Path | None = None,
) -> ImportResult:
    bundle_path = Path(bundle_path)
    data_db_dir = Path(data_db_dir)
    _assert_not_local_db(data_db_dir)

    owns_staging = staging_dir is None
    staging_path = Path(staging_dir) if staging_dir is not None else Path(tempfile.mkdtemp(prefix="azazel-bundle-"))
    new_gen_dir: Path | None = None
    swapped = False

    try:
        verified = verify_bundle(bundle_path, anchors_path, state_path, staging_path)
        manifest = verified.manifest
        if manifest["kind"] != "full":
            raise BundleImportError(f"import_full called with kind={manifest['kind']!r}")

        current = generations.current_generation(data_db_dir)
        next_n = 1 if current is None else current + 1

        intel_path = generations.build_next_generation(data_db_dir)
        new_gen_dir = intel_path.parent
        if intel_path.parent.name != f"{generations.GEN_DIR_PREFIX}{next_n}":
            raise BundleImportError("generation directory mismatch during full import")

        tables_applied: dict[str, int] = {}
        conn = sqlite3.connect(intel_path)
        try:
            apply_migrations(conn, "intel")
            for table in manifest.get("tables", []):
                _validate_identifier(table)
                path = verified.file_paths[f"tables/{table}.jsonl"]
                rows = _read_jsonl(path)
                tables_applied[table] = _insert_full_table(conn, table, rows)
            generations.bump_intel_generation(conn, next_n)
            conn.commit()
        finally:
            conn.close()

        _warm(intel_path)

        generations.swap_current(data_db_dir, next_n)
        swapped = True

        bundle_sha256 = _sha256_file(bundle_path)
        rollback_anchor.record_import(
            state_path,
            bundle_version=manifest["bundle_version"],
            imported_at=_now(),
            bundle_sha256=bundle_sha256,
        )

        removed = generations.gc_old_generations(data_db_dir, keep=2)
        return ImportResult(
            bundle_version=manifest["bundle_version"],
            tables=tables_applied,
            generation=next_n,
            removed_generations=removed,
        )
    except Exception:
        if not swapped and new_gen_dir is not None and new_gen_dir.exists():
            shutil.rmtree(new_gen_dir, ignore_errors=True)
        raise
    finally:
        if owns_staging:
            shutil.rmtree(staging_path, ignore_errors=True)


def apply_differential(
    bundle_path: str | Path,
    anchors_path: str | Path,
    state_path: str | Path,
    writer_conn: sqlite3.Connection,
    *,
    staging_dir: str | Path | None = None,
) -> ImportResult:
    """Apply a differential bundle to the live generation.

    `writer_conn` is a connection to the currently-live `intel.db`,
    owned by the caller (worker process); this function issues one
    transaction per table batch and never touches `local.db`.
    """
    bundle_path = Path(bundle_path)
    owns_staging = staging_dir is None
    staging_path = Path(staging_dir) if staging_dir is not None else Path(tempfile.mkdtemp(prefix="azazel-bundle-"))

    try:
        verified: VerifiedBundle = verify_bundle(bundle_path, anchors_path, state_path, staging_path)
        manifest = verified.manifest
        if manifest["kind"] != "differential":
            raise BundleImportError(f"apply_differential called with kind={manifest['kind']!r}")

        tables_applied: dict[str, int] = {}
        for table in manifest.get("tables", []):
            _validate_identifier(table)
            pk_cols = _table_pk_columns(writer_conn, table)
            path = verified.file_paths[f"deltas/{table}.jsonl"]
            deltas = _read_jsonl(path)

            writer_conn.execute("BEGIN IMMEDIATE")
            try:
                count = 0
                for delta in deltas:
                    op = delta["op"]
                    row = delta["row"]
                    if op == "upsert":
                        cols = sorted(row.keys())
                        placeholders = ",".join("?" for _ in cols)
                        writer_conn.execute(
                            f"INSERT OR REPLACE INTO {table} ({','.join(cols)}) VALUES ({placeholders})",
                            [row[c] for c in cols],
                        )
                    elif op == "delete":
                        if not pk_cols:
                            raise BundleImportError(f"table {table!r} has no primary key to delete by")
                        where = " AND ".join(f"{c} = ?" for c in pk_cols)
                        writer_conn.execute(
                            f"DELETE FROM {table} WHERE {where}",
                            [row[c] for c in pk_cols],
                        )
                    else:
                        raise BundleImportError(f"unknown delta op {op!r}")
                    count += 1
            except Exception:
                writer_conn.execute("ROLLBACK")
                raise
            else:
                writer_conn.execute("COMMIT")
            tables_applied[table] = count

        bundle_sha256 = _sha256_file(bundle_path)
        rollback_anchor.record_import(
            state_path,
            bundle_version=manifest["bundle_version"],
            imported_at=_now(),
            bundle_sha256=bundle_sha256,
        )
        return ImportResult(bundle_version=manifest["bundle_version"], tables=tables_applied)
    finally:
        if owns_staging:
            shutil.rmtree(staging_path, ignore_errors=True)
