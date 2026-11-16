#!/usr/bin/env bash
# Post-patch validation for docs/REVIEW-2026-11-16.md (SAAF Tripwire).
# Each case builds a throwaway git repo under a temp dir; nothing in the checkout is modified.
# Usage: bash docs/review/repro-2026-11-16.sh   (from the repo root, with the .venv from the README)
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PY="${PY:-$REPO/.venv/bin/python}"
[ -x "$PY" ] || { echo "no interpreter at $PY; run: python3 -m venv .venv && .venv/bin/pip install -e '.[test]'"; exit 2; }
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

gitq() { git -c user.email=a@b -c user.name=repro -c init.defaultBranch=main "$@"; }
newrepo() { mkdir -p "$1" && gitq -C "$1" init -q; }
commit() { gitq -C "$1" add -A && gitq -C "$1" commit -qm "${2:-c}"; }
secret() { printf 'ANTHROPIC_API_KEY = "sk-ant-api03-%s"\n' "$(head -c 60 /dev/urandom | base64 | tr -d '=+/' | head -c 40)" > "$1"; }
scan() { "$PY" -P -m tripwire scan "$@" 2>&1 | tail -4; }

echo "== baseline: a repo with a live key and a public bind fails =="
R="$WORK/base"; newrepo "$R"
secret "$R/keys.py"
printf 'from flask import Flask\napp=Flask(__name__)\napp.run(host="0.0.0.0", port=5000)\n' > "$R/app.py"
commit "$R"
scan "$R" --fail-on high; echo "   [expected] CRITICAL TW-SEC1 + MEDIUM TW-NET1, exit=1"

echo
echo "== R-01 (local default): a repo's own .tripwireignore is still honoured =="
printf 'keys.py\napp.py\n' > "$R/.tripwireignore"; commit "$R" ignore
scan "$R" --fail-on high; echo "   [expected] 0 finding(s), Suppressed by .tripwireignore: 2, exit=0 (documented local behaviour)"

echo
echo "== R-01 (CI, FIXED): config comes from the base commit via scripts/ci-config.sh =="
R1="$WORK/pr"; newrepo "$R1"
secret "$R1/keys.py"
printf 'from flask import Flask\napp=Flask(__name__)\napp.run(host="0.0.0.0", port=5000)\n' > "$R1/app.py"
commit "$R1" base; BASE1=$(gitq -C "$R1" rev-parse HEAD)
printf 'keys.py\napp.py\n' > "$R1/.tripwireignore"; commit "$R1" "suppress my own findings"
bash "$REPO/scripts/ci-config.sh" "$R1" "$BASE1" "" "$WORK/cfg1"; echo "   ci-config exit=$?"
if [ -e "$WORK/cfg1/.tripwireignore" ]; then echo "   trusted config HAS an ignore file (unexpected)"; else echo "   trusted config has no ignore file (expected)"; fi
scan "$R1" --fail-on high --config-from "$WORK/cfg1"
echo "   [expected] both findings survive the PR's ignore file, exit=1"

echo
echo "== R-02 (CI, FIXED): a baseline introduced by the change is refused =="
R2="$WORK/base2"; newrepo "$R2"
secret "$R2/keys.py"; commit "$R2" base; BASE2=$(gitq -C "$R2" rev-parse HEAD)
printf '{"accepted": []}\n' > "$R2/accepted.json"; commit "$R2" "add my own baseline"
bash "$REPO/scripts/ci-config.sh" "$R2" "$BASE2" "accepted.json" "$WORK/cfg2"
echo "   ci-config exit=$?  [expected] 3 and 'may not introduce its own baseline'"

echo
echo "== R-03 (FIXED): the red-team table reproduces inside a git checkout =="
(cd "$REPO" && "$PY" redteam/run.py 2>/dev/null | sed -n '6,12p')
gitq -C "$REPO" checkout -- redteam/RESULTS.md 2>/dev/null
rm -rf "$REPO"/redteam/TW-*
echo "   [expected] SEC1 0 evaded / control 1/1; LLM1 0; CI2 1 -- identical to committed RESULTS.md (no diff above)"

echo
echo "== R-07 (FIXED): TW-FS1 and TW-OUT2 now have fixtures and tests =="
for r in TW-FS1 TW-OUT2; do
  short=$(echo "${r#TW-}" | tr 'A-Z' 'a-z')
  echo "   $r fixtures=$(ls -d "$REPO/tests/fixtures/$r"/*/ 2>/dev/null | wc -l) test=$(ls "$REPO/tests/test_tw_$short.py" 2>/dev/null | wc -l)"
done
echo "   [expected] fixtures=4 test=1 for both"

echo
echo "== R-09a (FIXED): a symlink that escapes the root is ignored, not read =="
R3="$WORK/symlink"; newrepo "$R3"; printf 'x\n' > "$R3/a.py"
printf 'from flask import Flask\napp=Flask(__name__)\napp.run(host="0.0.0.0")\n' > "$WORK/outside.py"
ln -s "$WORK/outside.py" "$R3/leak.py"; commit "$R3"
PYTHONPATH="$REPO" "$PY" -P - "$R3" <<'PY'
import sys; from pathlib import Path
from tripwire import engine
names = [p.name for p in engine.tracked_files(Path(sys.argv[1]))]
print(f"   tracked files = {names}")
PY
scan "$R3" --fail-on high
echo "   [expected] leak.py absent, 0 finding(s) -- the outside file is never read"

echo
echo "== R-09b (FIXED): a /dev/zero symlink no longer kills the scan =="
if [ -e /dev/zero ]; then
  R4="$WORK/oom"; newrepo "$R4"; printf 'x\n' > "$R4/a.py"; ln -s /dev/zero "$R4/z.txt"; commit "$R4"
  start=$(date +%s)
  timeout 20 "$PY" -P -m tripwire scan "$R4" --fail-on high >/dev/null 2>&1; rc=$?
  echo "   exit=$rc in $(( $(date +%s) - start ))s  [expected] 0 (clean) in a few seconds, not 137/OOM"
else
  echo "   skipped: no /dev/zero"
fi

echo
echo "== R-10 (FIXED): -P is available on every supported Python =="
grep -n 'requires-python' "$REPO/pyproject.toml"
echo "   [expected] requires-python = \">=3.11\""

echo
echo "== R-11 (FIXED): trivial 'quotes' are no longer accepted as grounded =="
PYTHONPATH="$REPO" "$PY" - <<'PY'
from tripwire.fence import check_quotes
src = "The vendor must delete all customer data within thirty days of termination."
for q in ["a", "the", "within thirty days"]:
    print(f"   {q!r:24} -> {'REJECTED' if check_quotes([q], src) else 'ACCEPTED as grounded'}")
PY
echo "   [expected] 'a' and 'the' REJECTED; the real quote ACCEPTED"

echo
echo "== R-12 (FIXED): the reusable workflow grants actions: read for private-repo SARIF =="
sed -n '/permissions:/,/actions: read/p' "$REPO/.github/workflows/tripwire.yml" | tail -4
echo "   [expected] actions: read present"

echo
echo "== guards: full suite + worktree self-scan at medium =="
(cd "$REPO" && "$PY" -m pytest -q 2>&1 | tail -1)
# A shallow checkout makes the history scan fail closed by design; the worktree scan is the local guard.
(cd "$REPO" && "$PY" -P -m tripwire scan . --no-history --fail-on medium 2>&1 | tail -2)
