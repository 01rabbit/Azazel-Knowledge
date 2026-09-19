#!/usr/bin/env python3
"""CLI for building, signing, inspecting, and key-generating offline bundles.

Bundles are `.tar.gz` (see `azazel_knowledge.bundle.verify` module docstring for
why not `.tar.zst`), always with `manifest.json` then `manifest.sig` as
the first two tar members, followed by content files sorted by name.
Table dumps are ordered by primary key so identical source-database
content always produces byte-identical JSONL and therefore identical
manifest hashes, regardless of when or where the bundle is built.

Differential bundles in Phase 1 use a simple `--since` timestamp filter
against a best-guess timestamp column per table (`last_seen`,
`date_added`, or `created_at`) and emit every matched row as an
`upsert` -- there is no tombstone tracking yet, so deletes are not
produced by this tool (a Phase-2 TODO), only consumed by the importer.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import sqlite3
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from nacl.signing import SigningKey  # noqa: E402

from azazel_knowledge.bundle.lite_policy import load_export_policy  # noqa: E402
from azazel_knowledge.bundle.lite_select import (  # noqa: E402
    PROFILES,
    SelectionInputs,
    select_lite_content,
)
from azazel_knowledge.bundle.verify import (  # noqa: E402
    LOCAL_TIER_TABLES,
    MANIFEST_MEMBER,
    SIGNATURE_MEMBER,
    canonical_manifest_bytes,
    peek_manifest,
)

_EXCLUDED_TABLES = {"schema_migrations", "stats_meta"}
_SINCE_CANDIDATE_COLUMNS = ("last_seen", "date_added", "created_at")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _table_columns(conn: sqlite3.Connection, table: str) -> list[str]:
    return [row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()]


def _table_pk_columns(conn: sqlite3.Connection, table: str) -> list[str]:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    pk_rows = sorted((row for row in rows if row[5] > 0), key=lambda row: row[5])
    return [row[1] for row in pk_rows]


def _eligible_tables(conn: sqlite3.Connection) -> list[str]:
    names = [
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
    ]
    return sorted(
        n
        for n in names
        if n not in _EXCLUDED_TABLES and not n.startswith("_stage_") and n not in LOCAL_TIER_TABLES
    )


def _dump_table(conn: sqlite3.Connection, table: str, since: str | None) -> list[dict]:
    cols = _table_columns(conn, table)
    pk_cols = _table_pk_columns(conn, table) or cols
    order_by = ", ".join(pk_cols)
    ts_col = next((c for c in _SINCE_CANDIDATE_COLUMNS if c in cols), None)
    select = f"SELECT {', '.join(cols)} FROM {table}"
    params: tuple = ()
    if since and ts_col:
        select += f" WHERE {ts_col} >= ?"
        params = (since,)
    select += f" ORDER BY {order_by}"
    rows = conn.execute(select, params).fetchall()
    return [dict(zip(cols, row)) for row in rows]


def _jsonl_bytes(lines: list[dict]) -> bytes:
    buf = io.StringIO()
    for obj in lines:
        buf.write(json.dumps(obj, sort_keys=True, separators=(",", ":")))
        buf.write("\n")
    return buf.getvalue().encode("utf-8")


def _add_bytes(tar: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name=name)
    info.size = len(data)
    info.mtime = 0
    info.mode = 0o644
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    tar.addfile(info, io.BytesIO(data))


def cmd_keygen(args: argparse.Namespace) -> int:
    signing_key = SigningKey.generate()
    out_path = Path(args.out)
    out_path.write_text(signing_key.encode().hex(), encoding="utf-8")
    out_path.chmod(0o600)
    key_id = signing_key.verify_key.encode().hex()[:8]
    print(f"key_id: {key_id}")
    print(f"verify_key: {signing_key.verify_key.encode().hex()}")
    return 0


def _sign_manifest(manifest_bytes: bytes, sign_keys: list[str]) -> bytes:
    sig_lines = []
    for key_path in sign_keys:
        hex_key = Path(key_path).read_text(encoding="utf-8").strip()
        signing_key = SigningKey(bytes.fromhex(hex_key))
        key_id = signing_key.verify_key.encode().hex()[:8]
        signature = signing_key.sign(manifest_bytes).signature.hex()
        sig_lines.append(f"{key_id}:{signature}")
    return ("\n".join(sig_lines) + "\n").encode("utf-8")


def cmd_build(args: argparse.Namespace) -> int:
    kind = args.kind or ("differential" if args.base is not None else "full")
    if kind == "differential" and args.base is None:
        raise SystemExit("differential bundles require --base")

    conn = sqlite3.connect(f"file:{args.source_db}?mode=ro", uri=True)
    try:
        tables = _eligible_tables(conn)
        content_bytes: dict[str, bytes] = {}
        table_names: list[str] = []
        for table in tables:
            rows = _dump_table(conn, table, args.since)
            if kind == "differential":
                delta_lines = [{"op": "upsert", "row": row} for row in rows]
                content_bytes[f"deltas/{table}.jsonl"] = _jsonl_bytes(delta_lines)
            else:
                content_bytes[f"tables/{table}.jsonl"] = _jsonl_bytes(rows)
            table_names.append(table)
    finally:
        conn.close()

    files = {name: hashlib.sha256(data).hexdigest() for name, data in content_bytes.items()}

    manifest = {
        "bundle_version": args.version,
        "base_version": args.base,
        "kind": kind,
        "compression": "gzip",
        "created_at": _now(),
        "attack_version": args.attack_version or "",
        "feeds": sorted(args.feeds or []),
        "files": files,
        "tables": sorted(table_names),
    }
    manifest_bytes = canonical_manifest_bytes(manifest)

    sig_bytes = _sign_manifest(manifest_bytes, args.sign_key)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(out_path, mode="w:gz") as tar:
        _add_bytes(tar, MANIFEST_MEMBER, manifest_bytes)
        _add_bytes(tar, SIGNATURE_MEMBER, sig_bytes)
        for name in sorted(content_bytes):
            _add_bytes(tar, name, content_bytes[name])

    print(f"wrote {out_path} (bundle_version={args.version}, kind={kind}, tables={len(table_names)})")
    return 0


def _freshness_fields(conn: sqlite3.Connection, tables: list[str]) -> dict[str, str]:
    """Pick each table's freshness column from the fixed candidate list.

    The candidate order is a constant, and a table with none of the candidates
    is simply absent from the result, which makes it exempt from the freshness
    window. Static reference material such as ATT&CK techniques has no
    `last_seen`, and expiring it on a 30-day clock would be wrong rather than
    conservative.
    """
    fields: dict[str, str] = {}
    for table in tables:
        columns = set(_table_columns(conn, table))
        for candidate in _SINCE_CANDIDATE_COLUMNS:
            if candidate in columns:
                fields[table] = candidate
                break
    return fields


def cmd_build_lite(args: argparse.Namespace) -> int:
    """Build a signed Knowledge Lite bundle (ADR-0015).

    A Lite bundle is an ordinary bundle with a selection profile applied and a
    `profile` block in the manifest: same container, same member order, same
    signature scheme, same trust sourcing. A verifier that handles a full
    bundle handles this one unchanged.

    The manifest deliberately carries **no** `created_at`. ADR-0015 D2 requires
    the same selection tuple to produce a byte-identical unsigned artifact, and
    a wall-clock stamp would break that for no gain: the build instant that
    matters is the pinned `as_of`, which is recorded inside the profile block.
    """
    policy = load_export_policy(args.export_policy)
    alias_key = bytes.fromhex(Path(args.alias_key_file).read_text(encoding="utf-8").strip())
    if not alias_key:
        raise SystemExit("--alias-key-file must contain a non-empty hex key")

    inputs = SelectionInputs(
        intel_generation=args.intel_generation,
        stats_generation=args.stats_generation,
        attack_version=args.attack_version,
        config_hash=args.config_hash,
        profile_id=args.profile,
        export_policy_digest=policy.digest,
        as_of=args.as_of,
    )

    # Read-only URI: the builder cannot write to the source database even by
    # mistake, which is Absolute Constraint 5 enforced by the connection rather
    # than by discipline.
    conn = sqlite3.connect(f"file:{args.source_db}?mode=ro", uri=True)
    try:
        eligible = _eligible_tables(conn)
        # The export policy decides which datasets a Lite bundle carries. A
        # table the policy does not name is not "excluded" -- it was never
        # included, which is the same deny-by-default rule that governs fields
        # (ADR-0015 D5). Feeding every eligible table in and relying on the
        # ceiling to trim would be truncation by another name.
        named = sorted(set(policy.datasets) & set(eligible))
        missing = sorted(set(policy.datasets) - set(eligible))
        if missing:
            raise SystemExit(
                "export policy names dataset(s) that are not exportable intel tables in this "
                f"database: {missing}"
            )
        rows_by_dataset = {table: _dump_table(conn, table, None) for table in named}
        freshness_fields = _freshness_fields(conn, named)
    finally:
        conn.close()

    selection = select_lite_content(
        rows_by_dataset,
        inputs=inputs,
        policy=policy,
        alias_key=alias_key,
        scope=args.alias_scope,
        freshness_fields=freshness_fields,
    )

    content_bytes = {
        f"tables/{dataset}.jsonl": data for dataset, data in selection.content_bytes().items()
    }
    files = {name: hashlib.sha256(data).hexdigest() for name, data in content_bytes.items()}

    manifest = {
        "bundle_version": args.version,
        "base_version": None,
        "kind": "full",
        "compression": "gzip",
        "attack_version": args.attack_version,
        "feeds": [],
        "files": files,
        "tables": sorted(selection.datasets),
        "profile": selection.profile_block,
        # The artifact *claims* an epoch; whether the claim is acceptable is
        # decided locally from anchors.toml, never from here (F-7).
        "security_epoch": args.security_epoch,
    }
    manifest_bytes = canonical_manifest_bytes(manifest)
    sig_bytes = _sign_manifest(manifest_bytes, args.sign_key)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    # The gzip container is written with a zeroed header: `tarfile.open(mode="w:gz")`
    # stamps the current time into it, and an embedded filename varies with the
    # output path, so an otherwise identical rebuild would still differ byte for
    # byte. Tar member metadata is already fixed by `_add_bytes`. D2 claims a
    # byte-identical unsigned artifact for a repeated tuple, and that claim has
    # to hold for the artifact, not merely for its members.
    with out_path.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode="w") as tar:
                _add_bytes(tar, MANIFEST_MEMBER, manifest_bytes)
                _add_bytes(tar, SIGNATURE_MEMBER, sig_bytes)
                for name in sorted(content_bytes):
                    _add_bytes(tar, name, content_bytes[name])

    counts = selection.profile_block["counts"]
    print(
        f"wrote {out_path} (profile={args.profile}, datasets={counts['datasets']}, "
        f"rows={counts['rows']}, uncompressed_bytes={counts['uncompressed_bytes']})"
    )
    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    manifest = peek_manifest(args.bundle)
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bundle_build", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    build = sub.add_parser("build", help="build and sign a bundle from a source intel.db")
    build.add_argument("--source-db", required=True)
    build.add_argument("--out", required=True)
    build.add_argument("--version", type=int, required=True, dest="version")
    build.add_argument("--base", type=int, default=None)
    build.add_argument("--kind", choices=("full", "differential"), default=None)
    build.add_argument("--since", default=None)
    build.add_argument("--attack-version", default=None)
    build.add_argument("--feeds", nargs="*", default=None)
    build.add_argument("--sign-key", action="append", required=True, dest="sign_key")
    build.set_defaults(func=cmd_build)

    lite = sub.add_parser("build-lite", help="build and sign a bounded Knowledge Lite bundle (ADR-0015)")
    lite.add_argument("--source-db", required=True)
    lite.add_argument("--out", required=True)
    lite.add_argument("--version", type=int, required=True, dest="version")
    lite.add_argument("--profile", required=True, choices=sorted(PROFILES))
    lite.add_argument("--export-policy", required=True, help="path to the YAML export policy")
    lite.add_argument("--alias-key-file", required=True, help="file holding the hex alias key")
    lite.add_argument("--alias-scope", required=True, help="mission or request scope for aliases")
    lite.add_argument("--as-of", required=True, help="RFC 3339 instant the selection is pinned to")
    lite.add_argument("--intel-generation", type=int, required=True)
    lite.add_argument("--stats-generation", type=int, required=True)
    lite.add_argument("--attack-version", required=True)
    lite.add_argument("--config-hash", required=True)
    lite.add_argument(
        "--security-epoch",
        type=int,
        required=True,
        help="the security epoch this artifact is built under; a consumer refuses anything "
        "below its own anchors' minimum_security_epoch",
    )
    lite.add_argument("--sign-key", action="append", required=True, dest="sign_key")
    lite.set_defaults(func=cmd_build_lite)

    inspect = sub.add_parser("inspect", help="print a bundle's manifest without verifying trust")
    inspect.add_argument("bundle")
    inspect.set_defaults(func=cmd_inspect)

    keygen = sub.add_parser("keygen", help="generate an ed25519 signing key")
    keygen.add_argument("--out", required=True)
    keygen.set_defaults(func=cmd_keygen)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
