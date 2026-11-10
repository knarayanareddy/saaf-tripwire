"""Run Tripwire across the audited SAAF repos and score it against the confirmed audit findings.

Read-only on the audit workspace. Writes docs/evidence/SUMMARY.json and fills the README evidence table.

Definitions (stated in the README):
- A confirmed finding is IN SCOPE of a rule if the rule names its SA id (in RULE["seen_in"] or in
  docs/evidence/<RULE>.md); if a rule names no SA ids, findings in its seen_in repos with the same attack class.
- It is CAUGHT if that rule fires in the finding's repo on a file named in the finding's trace or fix
  (or anywhere in the repo when the finding has no file anchor, e.g. git-history secrets).
- recall = caught / in scope.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
from tripwire import cli, engine  # noqa: E402

SA = re.compile(r"SA-\d+")
START, END = "<!-- EVIDENCE:START -->", "<!-- EVIDENCE:END -->"


def anchors(f: dict, repos: set[str]) -> list[tuple[str, str]]:
    """(repo, path) pairs a hit can match."""
    out = []
    for t in f.get("trace", []) + [{"file": c.get("file_name", "")} for c in f.get("code", [])]:
        p = (t.get("file") or "").split(" (")[0].strip()
        if not p or p.startswith("(") or p.startswith("patches/") or "/patches/" in p:
            continue
        head = p.split("/", 1)
        if head[0] in repos and len(head) == 2:
            out.append((head[0], head[1]))
        else:
            out.append((f["repo"], p))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", default=str(Path.home() / "saaf-redteam/work"))
    ap.add_argument("--no-history", action="store_true")
    a = ap.parse_args()
    work = Path(a.work)
    repo_dir = work / "repos"
    repos = sorted(p.name for p in repo_dir.iterdir() if p.is_dir())
    confirmed = [f for f in json.loads((work / "findings/findings.json").read_text()) if f["verdict"] == "confirmed"]
    rules = [m.RULE for m in engine.load_rules()]

    hits: dict[str, dict[str, list]] = {r["id"]: {} for r in rules}
    t0 = time.time()
    slow = []
    for repo in repos:
        t = time.time()
        found, meta, _ = cli.scan(repo_dir / repo, history=not a.no_history, ignore_file="")
        for f in found:
            hits.setdefault(f.rule, {}).setdefault(repo, []).append((f.file, f.line, f.severity))
        if meta["errors"]:
            print(f"rule errors in {repo}: {meta['errors']}", file=sys.stderr)
        if time.time() - t > 10:
            slow.append(repo)

    caught_any = set()
    rows = []
    for r in rules:
        rid = r["id"]
        ev = HERE / "docs/evidence" / f"{rid}.md"
        ids = set(SA.findall(" ".join(r.get("seen_in", [])))) | (set(SA.findall(ev.read_text())) if ev.exists() else set())
        if ids:
            scope = [f for f in confirmed if f["id"] in ids]
        else:
            scope = [f for f in confirmed if f["repo"] in r.get("seen_in", []) and f["attackClass"] == r.get("class")]
        caught = []
        for f in scope:
            anc = anchors(f, set(repos))
            target_repos = {rp for rp, _ in anc} or {f["repo"]}
            ok = False
            for rp in target_repos:
                rh = hits.get(rid, {}).get(rp, [])
                paths = [p for x, p in anc if x == rp]
                if rh and (not paths or any(not h[0] or any(h[0] == p or h[0].endswith("/" + p) or p.endswith("/" + h[0]) for p in paths) for h in rh)):
                    ok = True
            if ok:
                caught.append(f["id"])
                caught_any.add(f["id"])
        rh = hits.get(rid, {})
        rows.append({"rule": rid, "title": r.get("title", ""), "severity": r.get("severity", ""),
                     "hits": sum(len(v) for v in rh.values()), "repos_hit": len(rh),
                     "in_scope": sorted(f["id"] for f in scope), "caught": sorted(caught),
                     "recall": (len(caught) / len(scope)) if scope else None,
                     "hit_repos": sorted(rh)})
    scoped = {i for row in rows for i in row["in_scope"]}
    summary = {"repos_scanned": len(repos), "seconds": round(time.time() - t0, 1), "slow_repos": slow,
               "confirmed_total": len(confirmed), "confirmed_in_scope": len(scoped),
               "caught_in_scope": len(caught_any & scoped), "caught_any": sorted(caught_any), "rules": rows}
    (HERE / "docs/evidence").mkdir(parents=True, exist_ok=True)
    (HERE / "docs/evidence/SUMMARY.json").write_text(json.dumps(summary, indent=2))

    lines = ["| Rule | What it stops | Hits (repos) | Confirmed findings in scope | Caught | Recall |",
             "|---|---|---|---|---|---|"]
    for row in rows:
        rec = "n/a" if row["recall"] is None else f"{row['recall']:.0%}"
        lines.append(f"| {row['rule']} | {row['title']} | {row['hits']} ({row['repos_hit']}) | "
                     f"{', '.join(row['in_scope']) or '-'} | {', '.join(row['caught']) or '-'} | {rec} |")
    tot = f"{len(caught_any & scoped)}/{len(scoped)}" if scoped else "0/0"
    lines.append("")
    lines.append(f"Scanned {len(repos)} repos in {summary['seconds']}s. Static rules catch **{tot}** of the confirmed "
                 f"findings they target; those are {len(scoped)} of all {len(confirmed)} confirmed findings. The rest "
                 f"(business logic, spec-to-code gaps, LLM output trust) are what the skill's method and `tripwire.fence` are for.")
    table = "\n".join(lines)
    readme = HERE / "README.md"
    txt = readme.read_text()
    if START in txt and END in txt:
        pre, rest = txt.split(START, 1)
        txt = pre + START + "\n" + table + "\n" + END + rest.split(END, 1)[1]
        readme.write_text(txt)
    print(table)
    return 0


if __name__ == "__main__":
    sys.exit(main())
