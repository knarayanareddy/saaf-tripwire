"""R-09: the guard treats the scanned repo as untrusted input — no symlink following, bounded reads."""
import os

import pytest

from tripwire import cli, engine
from tripwire.model import Context
from tripwire.util import safeio, webscan

APP = 'from flask import Flask\napp = Flask(__name__)\napp.run(host="0.0.0.0")\n'


def test_tracked_files_skips_symlinks_that_escape_the_root(tmp_path):
    outside = tmp_path / "outside.py"
    outside.write_text(APP)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "ok.py").write_text("x = 1\n")
    os.symlink(outside, repo / "leak.py")
    assert {p.name for p in engine.tracked_files(repo)} == {"ok.py"}


def test_webscan_files_skips_symlinks_even_when_ctx_files_is_set_by_hand(tmp_path):
    # The fixture runner builds ctx.files directly, so the filter must also live in webscan.files.
    outside = tmp_path / "outside.py"
    outside.write_text(APP)
    repo = tmp_path / "repo"
    repo.mkdir()
    ok = repo / "ok.py"
    ok.write_text("x = 1\n")
    leak = repo / "leak.py"
    os.symlink(outside, leak)
    ctx = Context(root=repo.resolve(), history=False)
    ctx.files = [ok, leak]
    assert [p.name for p in webscan.files(ctx, webscan.PY)] == ["ok.py"]


def test_no_finding_is_sourced_from_a_symlinked_file(tmp_path):
    outside = tmp_path / "outside.py"
    outside.write_text(APP)
    repo = tmp_path / "repo"
    repo.mkdir()
    os.symlink(outside, repo / "leak.py")
    findings, _, _ = cli.scan(repo, history=False)
    assert not [f for f in findings if f.file == "leak.py"]


@pytest.mark.skipif(not os.path.exists("/dev/zero"), reason="needs /dev/zero")
def test_device_symlink_is_refused_and_never_read(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    link = repo / "z.txt"
    os.symlink("/dev/zero", link)
    assert safeio.is_safe_file(link, repo) is False
    assert safeio.read_text(link) == ""          # returns immediately: no unbounded read


def test_out_of_root_path_is_refused(tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("x")
    repo = tmp_path / "repo"
    repo.mkdir()
    assert safeio.is_safe_file(outside, repo) is False
    assert safeio.is_safe_file(repo / "missing.txt", repo) is False
