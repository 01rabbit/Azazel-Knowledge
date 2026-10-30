"""Serialised, crash-safe access to `anchors.toml`.

Every reader that acts on the trust anchors (bundle import) and every writer
(`azctl keys ...`, `azctl provision`) goes through `anchors_lock`, a `flock`
on a sibling file that is never replaced. Writers hold it exclusively across
the whole read -> modify -> validate -> write, so one command cannot write
back a document read before another command's revocation. Importers hold it
shared from the moment they read the anchors until the import has been
recorded, so a revocation is linearised against imports: an import that
started before the revocation finishes under the trust it read, and the
revocation waits for it; an import that starts after the revocation returned
sees it.

The lock and the document must name the same file, or an alias would let an
import read the anchors under a different lock. The document is therefore
read only through the given path with no final-component symlink, and must
be a regular file with a single link: a symlink or a hard link to
`anchors.toml` is refused by readers and writers alike. Directory components
may be symlinks; the lock is a sibling in the same resolved directory, so it
is the same lock.

`write_anchors_atomic` takes the held exclusive lock rather than a path, so
it cannot be called outside the lock. It never truncates the live file: it
writes a 0600 temporary created exclusively in the same directory, fsyncs it,
renames it over the anchors and fsyncs the directory, so a crash leaves
either the old or the complete new document.
"""

from __future__ import annotations

import contextlib
import errno
import fcntl
import os
import secrets
import stat
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path


class AnchorsStoreError(Exception):
    pass


class AnchorsPathUnsafe(AnchorsStoreError):
    """The anchors path is a symlink, a hard link, or not a regular file."""


def lock_path_for(anchors_path: str | Path) -> Path:
    path = Path(anchors_path)
    return path.with_name(path.name + ".lock")


@dataclass
class AnchorsLock:
    anchors_path: Path
    exclusive: bool
    held: bool = True


@contextlib.contextmanager
def anchors_lock(anchors_path: str | Path, *, shared: bool) -> Iterator[AnchorsLock]:
    lock_path = lock_path_for(anchors_path)
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_SH if shared else fcntl.LOCK_EX)
        handle = AnchorsLock(Path(anchors_path), exclusive=not shared)
        try:
            yield handle
        finally:
            handle.held = False
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _check_regular_single_link(st: os.stat_result, path: Path) -> None:
    if not stat.S_ISREG(st.st_mode):
        raise AnchorsPathUnsafe(f"anchors path is not a regular file: {path}")
    if st.st_nlink != 1:
        raise AnchorsPathUnsafe(f"anchors file has {st.st_nlink} hard links; refusing an aliased file: {path}")


def read_anchors_bytes(anchors_path: str | Path) -> bytes:
    """The anchors document, read without following a symlink. FileNotFoundError if absent."""
    path = Path(anchors_path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise AnchorsPathUnsafe(f"anchors path is a symlink: {path}") from None
        raise
    with os.fdopen(fd, "rb") as fh:
        _check_regular_single_link(os.fstat(fh.fileno()), path)
        return fh.read()


def write_anchors_atomic(lock: AnchorsLock, text: str) -> None:
    if not (lock.held and lock.exclusive):
        raise AnchorsStoreError("anchors may only be written while holding the exclusive anchors lock")
    path = lock.anchors_path
    if os.path.lexists(path):  # also a dangling symlink, which lstat reports as not regular
        _check_regular_single_link(os.lstat(path), path)
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
