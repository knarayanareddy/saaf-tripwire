"""Bounded, symlink-safe file access for everything that reads a scanned repository.

A scanned repo is untrusted input. Two failures matter to the guard itself (both were real: see
docs/REVIEW-2026-11-16.md, R-09):

* a symlink such as ``leak.txt -> ~/.ssh/id_rsa`` makes a rule read an operator file; and
* a symlink to ``/dev/zero`` makes ``read_text()`` allocate without bound and OOM the scanner.

Every path that comes from a repository walk goes through :func:`is_safe_file` and :func:`read_text`,
which refuse symlinks, non-regular files, paths that resolve outside the scanned root, and files above
a fixed size cap.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

#: Largest file any rule will read. Regex/AST work on huge minified bundles is not worth the memory;
#: 8 MB covers the largest file seen in the 50-repo SAAF scan with headroom.
MAX_BYTES = 8_000_000


def is_safe_file(path: Path, root: Path | None = None) -> bool:
    """True only for a regular, non-symlink file of bounded size inside ``root`` (when given)."""
    try:
        st = os.lstat(path)                      # lstat: never follow the link itself
    except OSError:
        return False
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        return False
    if st.st_size > MAX_BYTES:
        return False
    if root is not None:
        try:
            resolved = Path(path).resolve()
            base = Path(root).resolve()
        except OSError:
            return False
        if resolved != base and base not in resolved.parents:
            return False
    return True


def read_text(path: Path, limit: int = MAX_BYTES) -> str:
    """Read at most ``limit`` characters; return "" on any error. Never follows a symlink."""
    try:
        if os.path.islink(path):
            return ""
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(limit)
    except OSError:
        return ""


def walk(root: Path, pattern: str = "*"):
    """Yield safe files under ``root`` matching ``pattern`` (same semantics as ``root.rglob``)."""
    root = Path(root)
    for p in root.rglob(pattern):
        if is_safe_file(p, root):
            yield p
