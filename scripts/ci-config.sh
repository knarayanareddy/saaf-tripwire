#!/usr/bin/env bash
# Resolve the guard's control-plane config (.tripwireignore, baseline) for a scan.
#
# On a pull request the config is taken from the BASE commit, so the change under test cannot
# silence the findings it introduces (review R-01/R-02). Without a usable base (push, manual run,
# shallow checkout) the repo's own reviewed config is used and a warning is printed.
#
# Usage: ci-config.sh <target-repo> <base-sha|""> <baseline-name|""> <dest-dir>
# Exit:  0 = config directory prepared, 3 = baseline named but absent from the base commit
set -uo pipefail

target=${1:?target repo}
base=${2:-}
baseline=${3:-}
dest=${4:?destination}
mkdir -p "$dest"

if [ -n "$base" ] && git -C "$target" cat-file -e "$base^{commit}" 2>/dev/null; then
  # The base is a real commit: use only what it contains.
  if git -C "$target" cat-file -e "$base:.tripwireignore" 2>/dev/null; then
    git -C "$target" show "$base:.tripwireignore" > "$dest/.tripwireignore"
  fi
  if [ -n "$baseline" ]; then
    if git -C "$target" cat-file -e "$base:$baseline" 2>/dev/null; then
      git -C "$target" show "$base:$baseline" > "$dest/baseline.json"
    else
      echo "baseline '$baseline' does not exist at the base commit; a change may not introduce its own baseline" >&2
      exit 3
    fi
  fi
else
  [ -n "$base" ] && echo "::warning::base commit $base is not available (shallow checkout?); trusting the checkout's own config" >&2
  [ -f "$target/.tripwireignore" ] && cp "$target/.tripwireignore" "$dest/.tripwireignore"
  if [ -n "$baseline" ] && [ -f "$target/$baseline" ]; then
    cp "$target/$baseline" "$dest/baseline.json"
  fi
fi
exit 0
