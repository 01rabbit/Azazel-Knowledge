"""Serialised, crash-safe access to `anchors.toml`.

Every reader that acts on the trust anchors (bundle import) and every writer
(`azctl keys ...`) goes through `anchors_lock`, a `flock` on a sibling file
that is never replaced. Writers hold it exclusively across the whole
read -> modify -> validate -> write, so one operator command cannot write back
a document read before another command's revocation. Importers hold it shared
from the moment they read the anchors until the import has been recorded, so
a revocation is linearised against imports: an import that started before the
revocation finishes under the trust it read, and the revocation waits for it;
an import that starts after the revocation returned sees it.

`write_anchors_atomic` never truncates the live file: it writes a 0600
temporary created exclusively in the same directory, fsyncs it, renames it
over the anchors and fsyncs the directory, so a crash leaves either the old or
the complete new document. A symlinked anchors path is refused rather than
followed, so the command never rewrites whatever the link points at.
"""

from __future__ import annotations

import contextlib
import fcntl
import os
import secrets
from collections.abc import Iterator
from pathlib import Path


class AnchorsStoreError(Exception):
    pass


def lock_path_for(anchors_path: str | Path) -> Path:
    path = Path(anchors_path)
    return path.with_name(path.name + ".lock")


@contextlib.contextmanager
def anchors_lock(anchors_path: str | Path, *, shared: bool) -> Iterator[None]:
    lock_path = lock_path_for(anchors_path)
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_SH if shared else fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def write_anchors_atomic(anchors_path: str | Path, text: str) -> None:
    path = Path(anchors_path)
    if path.is_symlink():
        raise AnchorsStoreError(f"refusing to write through a symlink: {path}")
    if path.exists() and not path.is_file():
        raise AnchorsStoreError(f"anchors path is not a regular file: {path}")
    data = text.encode("utf-8")
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        try:
            os.fchmod(fd, 0o600)
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise
    dir_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
