"""Helpers for the supply-chain/secrets rule tests (TW-SEC1, TW-CI*, TW-DEP1).

Fixtures never contain real-looking secrets on disk (push protection, and Tripwire scanning itself):
@@ANTHROPIC@@-style tokens are expanded at test time into deterministic, high-entropy fake values.
A fixture with commit1/, commit2/ ... subfolders is replayed as successive git commits (history cases).
"""
import hashlib, shutil, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tripwire.model import Context  # noqa: E402
from tripwire.engine import tracked_files  # noqa: E402

FIX = Path(__file__).parent / "fixtures"
B62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


def rnd(seed: str, n: int, alphabet: str = B62) -> str:
    out, h = "", seed.encode()
    while len(out) < n:
        h = hashlib.sha256(h).digest()
        out += "".join(alphabet[b % len(alphabet)] for b in h)
    return out[:n]


TOKENS = {
    "@@ANTHROPIC@@": "sk-ant-api03-" + rnd("ant", 95),
    "@@GITHUB@@": "ghp" + "_" + rnd("gh", 36),
    "@@AWS@@": "AK" + "IA" + rnd("aws", 16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"),
    "@@HIGHENTROPY@@": rnd("hi", 44),
    "@@STRIPE@@": "sk" + "_live_" + rnd("stripe", 99),
    "@@HF@@": "hf" + "_" + rnd("hf", 34),
}


def _expand(dst: Path):
    for p in dst.rglob("*"):
        if p.is_file() and ".git" not in p.relative_to(dst).parts:
            raw = p.read_bytes()
            enc = "utf-16" if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else "utf-8"
            t = raw.decode(enc)
            for k, v in TOKENS.items():
                t = t.replace(k, v)
            p.write_bytes(t.encode(enc))


def _git(d, *a):
    subprocess.run(["git", "-C", str(d), *a], check=True, capture_output=True,
                   env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
                        "GIT_COMMITTER_EMAIL": "t@t", "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
                        "HOME": str(d)})


def materialize(rule: str, case: str, tmp: Path, git: bool = True) -> Path:
    src = FIX / rule / case
    dst = tmp / case
    commits = sorted(p for p in src.iterdir() if p.is_dir() and p.name.startswith("commit"))
    dst.mkdir(parents=True)
    if git:
        _git(dst, "init", "-q")
    if commits:
        for c in commits:
            for p in list(dst.iterdir()):
                if p.name != ".git":
                    shutil.rmtree(p) if p.is_dir() else p.unlink()
            shutil.copytree(c, dst, dirs_exist_ok=True)
            _expand(dst)
            _git(dst, "add", "-A")
            _git(dst, "commit", "-q", "-m", c.name)
    else:
        shutil.copytree(src, dst, dirs_exist_ok=True)
        _expand(dst)
        if git:
            _git(dst, "add", "-A")
            _git(dst, "commit", "-q", "-m", "fixture")
    return dst


def run_rule(mod, root: Path, history: bool = True):
    ctx = Context(root=root.resolve(), history=history)
    ctx.files = tracked_files(ctx.root)
    return mod.check(ctx)


def cases(rule: str, prefix: str):
    return sorted(p.name for p in (FIX / rule).iterdir() if p.name.startswith(prefix))
