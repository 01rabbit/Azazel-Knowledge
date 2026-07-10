"""Static contract: `api/` and `taxii/` never open a write-mode SQLite
connection (design S2 -- "Read-only WAL connections only; a static
contract test asserts no router module can open a write-mode
connection"). Every DML keyword and the two bulk-write cursor methods
are grepped as whole words, case-insensitively, across every `.py` file
in both packages; the only legitimate mutation path from this layer is
the durable file-based `SpoolWriter`, which never touches SQLite.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
API_DIR = REPO_ROOT / "src" / "azazel_knowledge" / "api"
TAXII_DIR = REPO_ROOT / "src" / "azazel_knowledge" / "taxii"

_FORBIDDEN = re.compile(
    r"\b(INSERT|UPDATE|DELETE|executemany|executescript)\b", re.IGNORECASE
)
_CONNECT = re.compile(r"sqlite3\.connect\s*\(")


def _all_py_files() -> list[Path]:
    files: list[Path] = []
    for base in (API_DIR, TAXII_DIR):
        files.extend(sorted(base.rglob("*.py")))
    return files


def test_no_write_statement_patterns_in_api_or_taxii():
    offenders: list[str] = []
    for path in _all_py_files():
        text = path.read_text(encoding="utf-8")
        for line_no, line in enumerate(text.splitlines(), start=1):
            if _FORBIDDEN.search(line):
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{line_no}: {line.strip()}")
    assert not offenders, "forbidden write pattern(s) found:\n" + "\n".join(offenders)


def test_sqlite_connect_only_used_for_declared_read_only_helpers():
    """`sqlite3.connect` may appear only in the two helpers that
    immediately set `PRAGMA query_only = ON` before any other
    statement (`app.open_local_readonly` and its internal
    `_lookup_client` auth path); every other module must go through
    `Repository`, which already enforces the same pragma."""
    allowed_files = {API_DIR / "app.py"}
    for path in _all_py_files():
        if _CONNECT.search(path.read_text(encoding="utf-8")):
            assert path in allowed_files, f"unexpected sqlite3.connect in {path}"


def test_api_and_taxii_modules_exist():
    assert (API_DIR / "app.py").is_file()
    assert (API_DIR / "routers" / "context.py").is_file()
    assert (TAXII_DIR / "inbox.py").is_file()
