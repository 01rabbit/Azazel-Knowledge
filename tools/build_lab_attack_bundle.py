#!/usr/bin/env python3
"""LAB ONLY: build a signed synthetic ATT&CK bundle for isolated interop tests.

The bundle carries invented technique rows, never real ATT&CK content, and
must not be imported into a production Knowledge node. It exists so a
cross-product lab (Nexus <-> Knowledge) can exercise the technique lookup with
known corpora: found, no_match (an ID deliberately left out), stale, and
unavailable variants.

Flow (the official path, nothing is injected into a running Knowledge):

1. `AttackAdapter(fetch_bytes=...)` loads synthetic STIX into a scratch
   intel.db (the only use of `fetch_bytes`; it prepares the artifact).
2. `tools/bundle_build.py build` signs that database as a full bundle.
3. The lab imports the bundle with `azctl` / `bundle.importer.import_full`
   and starts the real listener.

Variants are produced from the input, not by patching a live database:
`--last-success` (old value -> stale, future -> unavailable),
`--feed-disabled` (halted feed -> unavailable), `--attack-version`.

Example:
    python tools/build_lab_attack_bundle.py --out lab.tar.gz --version 1 \\
        --sign-key lab.key --technique "T1110|Brute Force|credential-access" \\
        --technique "T1595.002|Vulnerability Scanning|reconnaissance" \\
        --last-success 2026-07-05T00:00:00Z
(T1566 is intentionally absent from the defaults so it answers no_match.)
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from azazel_knowledge.core.clock import FixedClock, parse_rfc3339  # noqa: E402
from azazel_knowledge.db.repository import apply_migrations  # noqa: E402
from azazel_knowledge.db.writer import PrioritySingleWriterQueue  # noqa: E402
from azazel_knowledge.feeds.adapters.attack import AttackAdapter  # noqa: E402

DEFAULT_TECHNIQUES = (
    "T1110|Brute Force|credential-access",
    "T1110.001|Password Guessing|credential-access",
    "T1595.002|Vulnerability Scanning|reconnaissance",
)


def synthetic_stix(techniques: list[str], attack_version: str) -> bytes:
    """Minimal STIX 2.1 bundle. Each spec is `ID|Name|tactic[,tactic]`."""
    objects: list[dict] = [{
        "type": "x-mitre-collection", "id": "x-mitre-collection--00000000-0000-4000-8000-0000000000c0",
        "name": "LAB synthetic ATT&CK", "x_mitre_version": attack_version, "spec_version": "2.1",
    }]
    for index, spec in enumerate(techniques):
        technique_id, name, tactics = spec.split("|")
        objects.append({
            "type": "attack-pattern",
            "id": f"attack-pattern--00000000-0000-4000-8000-{index:012x}",
            "name": name,
            "description": "LAB synthetic technique",
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": t}
                                  for t in tactics.split(",")],
            "external_references": [{"source_name": "mitre-attack", "external_id": technique_id}],
            "x_mitre_is_subtechnique": "." in technique_id,
        })
    return json.dumps({"type": "bundle", "id": "bundle--00000000-0000-4000-8000-000000000001",
                       "objects": objects}).encode()


def build_source_db(db_path: Path, techniques: list[str], attack_version: str,
                    last_success: str, feed_disabled: bool) -> None:
    conn = sqlite3.connect(db_path)
    apply_migrations(conn, "intel")
    conn.commit()
    conn.close()
    writer = PrioritySingleWriterQueue(db_path, db_path.with_suffix(".lock"))
    writer.open()
    try:
        adapter = AttackAdapter(
            "attack", {"kind": "attack_stix", "group": "mitre"}, writer,
            clock=FixedClock(parse_rfc3339(last_success)),
            fetch_bytes=lambda: synthetic_stix(techniques, attack_version),
        )
        outcome = adapter.run()
        if outcome.status != "applied":
            raise SystemExit(f"synthetic ATT&CK load failed: {outcome.status}")
    finally:
        writer.close()
    if feed_disabled:
        conn = sqlite3.connect(db_path)
        conn.execute("UPDATE feed_state SET enabled = 0 WHERE feed_id = 'attack'")
        conn.commit()
        conn.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="build_lab_attack_bundle", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", required=True)
    parser.add_argument("--version", type=int, required=True, help="bundle_version")
    parser.add_argument("--sign-key", action="append", required=True, dest="sign_key")
    parser.add_argument("--technique", action="append", dest="techniques",
                        help="ID|Name|tactic[,tactic] (repeatable); default: three lab rows")
    parser.add_argument("--attack-version", default="15.1")
    parser.add_argument("--last-success", default=None,
                        help="RFC 3339 instant stored as feed_state.last_success (default: now)")
    parser.add_argument("--feed-disabled", action="store_true")
    args = parser.parse_args(argv)
    last_success = args.last_success or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    techniques = args.techniques or list(DEFAULT_TECHNIQUES)
    with tempfile.TemporaryDirectory(prefix="azn-lab-attack-") as scratch:
        source = Path(scratch) / "source_intel.db"
        build_source_db(source, techniques, args.attack_version, last_success, args.feed_disabled)
        command = [sys.executable, str(Path(__file__).resolve().parent / "bundle_build.py"), "build",
                   "--source-db", str(source), "--out", args.out, "--version", str(args.version),
                   "--attack-version", args.attack_version, "--feeds", "attack"]
        for key in args.sign_key:
            command += ["--sign-key", key]
        result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        return result.returncode
    sys.stdout.write(result.stdout)
    print("LAB ONLY: synthetic ATT&CK content; do not import into production")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
