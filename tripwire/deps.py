"""Optional ONLINE dependency-advisory gate (the only part of Tripwire that uses the network).

- npm: `npm audit --audit-level=critical --package-lock-only` per package-lock.json (reads the lock file only;
  never runs install scripts from the repo under test).
- Python: `pip-audit -r <file> --no-deps --disable-pip` per requirements*.txt (audits the pinned list without
  installing or building anything from the repo; PyPI advisories carry no reliable severity, so any known
  advisory on a pinned version fails — stricter than "critical").
Exit 1 if any audit fails; unpinned requirement files are reported as a warning, not a failure.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

SKIP = {".git", "node_modules", ".venv", "venv", "dist", "build", ".tripwire-src"}


def _files(root: Path, pattern: str):
    for p in sorted(root.rglob(pattern)):
        if not (set(p.relative_to(root).parts) & SKIP):
            yield p


def main(argv: list[str] | None = None) -> int:
    root = Path((argv or sys.argv[1:] or ["."])[0]).resolve()
    failed = 0
    if shutil.which("npm"):
        for lock in _files(root, "package-lock.json"):
            r = subprocess.run(["npm", "audit", "--audit-level=critical", "--package-lock-only"], cwd=lock.parent)
            print(f"npm audit {lock.relative_to(root)}: {'FAIL' if r.returncode else 'ok'}")
            failed |= r.returncode != 0
    for req in _files(root, "requirements*.txt"):
        r = subprocess.run(["pip-audit", "-r", str(req), "--no-deps", "--disable-pip", "--progress-spinner", "off"],
                           capture_output=True, text=True)
        rel = req.relative_to(root)
        if r.returncode == 0:
            print(f"pip-audit {rel}: ok")
        elif "Found" in r.stdout and "vulnerab" in r.stdout:
            print(f"pip-audit {rel}: FAIL\n{r.stdout}")
            failed = 1
        else:
            print(f"::warning::pip-audit could not audit {rel} without installing it (unpinned?): "
                  f"{(r.stderr or r.stdout).strip()[:300]}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
