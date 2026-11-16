# Phase 1 — Reconnaissance: SAAF Tripwire as the target

**Target** `SAAF-Project/saaf-tripwire` @ `281bbcd` + the working-tree fixes from `docs/REVIEW-2026-11-16.md`
**Date** 2026-11-16 · **Method** the six-phase workflow from `cloudflare/security-audit-skill`, plus
spec-to-code / sharp-edges / variant-analysis lenses.
**Rule** every confirmed record below has an executed probe and a one-line observed result; anything I could
not run is in `NEEDS-VALIDATION.md`, never in the findings.

## 1. What the target is

```
              ┌──────────────────────────────┐
 scanned repo │  engine.tracked_files()      │  git ls-files / rglob
  (UNTRUSTED) │        │                     │
              │        ▼                     │
              │  16 rule modules ── findings │
              │        │                     │
              │        ▼                     │
              │  report: text / JSON / SARIF │
              └────────┬─────────────────────┘
                       │
     ┌─────────────────┼──────────────────┬────────────────────┐
     ▼                 ▼                  ▼                    ▼
  CLI stdout      action.yml         reusable wf          skill prompt
 (CI logs)     (CI gate, SARIF)     (base-ref config)     (agent context)
```

## 2. Entrypoints (enumerated mechanically)

| Surface | Entry | Reads | Writes / emits |
|---|---|---|---|
| CLI | `tripwire scan <path>`, `rules` | repo files, `.git`, `.tripwireignore`, baseline | stdout, `-o`, `--sarif-out` |
| Engine | `engine.run()`, `cli.scan()` | worktree | `Finding` records |
| Rule modules | 16 `check(ctx)` | file bytes, AST, git history | findings |
| Git helper | `git ls-files`, `git log -p` | `.git/config`, `.gitattributes`, objects | — |
| Composite action | `action.yml` (7 steps) | inputs, base commit config | SARIF, `$GITHUB_OUTPUT`, exit code |
| Reusable workflow | `.github/workflows/tripwire.yml` | caller inputs | job result |
| Deps gate | `tripwire/deps.py` (optional, online) | `requirements*.txt`, `package-lock.json` | subprocesses |
| Runtime guard | `tripwire/fence.py` | auditee documents | prompt text |
| Skill | `skill/.../SKILL.md` | scan output, repo | model context |

## 3. Trust boundaries (where data changes hands)

| # | Boundary | Direction | Notes |
|---|---|---|---|
| B1 | scanned repo → scanner | untrusted in | every file, filename, symlink, device |
| B2 | scanned repo `.git` → git | untrusted in | config, attributes, hooks path, objects |
| B3 | git process → OS | **executable** | `textconv`, `core.fsmonitor` (the two found) |
| B4 | scanner → CI log | out | text report is line-oriented; CI parses `::` commands |
| B5 | scanner → SARIF consumer | out | JSON, file URIs |
| B6 | scanner → agent/model | out | evidence/messages; consumed by the skill |
| B7 | repo config → scanner control plane | untrusted in | `.tripwireignore`, baseline (fixed in `docs/REVIEW`) |
| B8 | workflow author → action | semi-trusted | inputs, base SHA |
| B9 | package index → build | untrusted in | build backend, PyYAML wheel |
| B10 | caller repo → reusable workflow | untrusted ref | `tripwire-ref` must be a full SHA |

## 4. Prior evidence carried forward (not re-counted)

`docs/REVIEW-2026-11-16.md` confirmed and fixed: control-plane bypass via `.tripwireignore`/baseline (R-01/02),
symlink read + `/dev/zero` OOM (R-09), `-P` on 3.10 (R-10), trivial quotes (R-11), private-repo SARIF (R-12).
Those fixes are inputs to this audit; their regressions remain in the suite.

## 5. Coverage ledger

`coverage-ledger.json` — 18 units, every one `covered` (with the owning check and its result) or `out_of_scope`
(with a named reason). Validated by `validate.py`.

## 6. Stop condition

Audit ends when every ledger unit is covered or named out of scope, every confirmed record has a passing probe,
and every rejected candidate has the observation that killed it. No open-ended fuzzing was attempted; the
resource-exhaustion units are bounded by the checks named there.
