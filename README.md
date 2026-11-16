# SAAF Tripwire

**One guard that stops the bad actors we actually found.** Built from a probe-backed security audit of all
50 SAAF-Project repositories, it runs in seconds on every push and on every pull request.

## The problem
SAAF agents read documents written by the people they audit, run on laptops and shared servers, and ship through
GitHub Actions. That makes three kinds of bad actor real: someone on the same network or a web page in the
operator's browser, an auditee who plants text in a document, and anyone who can touch the CI supply chain.

## What we found across 50 repos
We audited every repository and only counted what we could execute: **44 confirmed findings** (6 high,
17 medium, 21 low), **40 rejected candidates** with the payload that disproved them, **114 deterministic
probes**, and all **44 fixes proven in a staging copy** (vulnerable before, fixed after). Examples:
servers on `0.0.0.0` with no login, `CORS *` letting any web page drive a local agent, real API keys left in
git history, a CI guard that the scanned repo could replace with its own code, and agents that accepted
quotes that never existed in the source.

## One guard, three ways to use it
Tripwire is one deterministic Python engine (offline, no LLM calls, whole repo in seconds). Every rule cites
the audit findings it would have caught (`tripwire rules`).

| Way | What it is | Who it is for |
|---|---|---|
| **CI check** | `action.yml`: scans, fails the build at your threshold, shows findings inline on PRs (SARIF) | any repo |
| **Reusable workflow** | `.github/workflows/tripwire.yml`: full-history secret scan, least privilege, every action SHA-pinned | adopt in 3 lines |
| **Claude Code skill** | `skill/saaf-tripwire/SKILL.md`: the audit method + the runtime prompt-injection guard (`tripwire.fence`) | agents and auditors |

## Adopt in 3 lines
Add `.github/workflows/tripwire.yml` to your repo (full file in `examples/caller.yml`):
```yaml
jobs:
  tripwire:
    uses: SAAF-Project/saaf-tripwire/.github/workflows/tripwire.yml@<release-sha>
    with: { tripwire-ref: "<release-sha>" }
```
Already have findings you can't fix today? Accept them once and only fail on new ones:
`tripwire scan . --write-baseline .tripwire-baseline.json`, then pass `baseline: .tripwire-baseline.json`.

## Run it locally
```
pip install .
python -P -m tripwire scan <repo> --fail-on high      # --format text|json|sarif, --only TW-NET1, --no-history
python -P -m tripwire rules
```
Exit 0 = clean, 1 = findings at or above `--fail-on`, 2 = guard error (it fails closed). `-P` stops the scanned
repo from shadowing the guard. Secrets are always masked after 4 characters.

The history scan refuses to run on a **shallow clone** (exit 2) rather than report a false clean: in CI set
`fetch-depth: 0` on `actions/checkout`, or scan without history locally with `--no-history`.

In CI, pass `--config-from <trusted-dir>`: the action uses the base commit, so the change under test cannot
hide its own findings behind a `.tripwireignore` or a baseline it introduces (`action.yml`, review R-01/R-02).

## The guard practises what it preaches
Every action is pinned to a full commit SHA, the workflow has `contents: read`, `security-events: write` and
`actions: read` only, no event data is expanded inside a shell, the guard runs with `python -P`, and the repo passes its own
scan at `--fail-on medium` (`.github/workflows/self-scan.yml`). The guard has also been run through its own
methodology; the nine defects that found are in `docs/self-audit/REPORT.md`.

## Evidence: Tripwire run across the 50 audited repos
Filled by `scripts/evidence.py`. A confirmed finding is *in scope* of a rule when the rule names it; it is
*caught* when the rule fires in that repo on a file in the finding's trace. Recall = caught / in scope.

<!-- EVIDENCE:START -->
| Rule | What it stops | Hits (repos) | Confirmed findings in scope | Caught | Recall |
|---|---|---|---|---|---|
| TW-CI1 | Third-party GitHub Action not pinned to a full commit SHA | 47 (9) | SA-24, SA-41 | SA-24, SA-41 | 100% |
| TW-CI2 | Workflow injection or over-broad token scope | 2 (2) | SA-24 | - | 0% |
| TW-CI3 | CI guard can be replaced by a same-named module in the scanned repo | 1 (1) | SA-41 | SA-41 | 100% |
| TW-DEP1 | Unpinned dependencies in a network-facing app or CI install | 12 (10) | SA-03 | - | 0% |
| TW-FS1 | Tree walk follows symlinks / upload filename path traversal | 22 (12) | SA-37 | SA-37 | 100% |
| TW-GATE1 | Fail-open gate: failure is only logged, or unknown input defaults to PASS | 27 (14) | SA-04, SA-05, SA-08, SA-14, SA-23 | SA-04, SA-05, SA-08, SA-14, SA-23 | 100% |
| TW-KEY1 | Server secret reaches the browser | 4 (4) | SA-29 | SA-29 | 100% |
| TW-LLM1 | Untrusted content reaches an LLM prompt without a fence | 97 (21) | SA-20, SA-30, SA-38, SA-39 | SA-20, SA-30, SA-38, SA-39 | 100% |
| TW-LLM2 | LLM verdict accepted without validation or quote check | 24 (12) | SA-14, SA-20, SA-31 | SA-14, SA-20, SA-31 | 100% |
| TW-NET1 | Server listens on all interfaces with no authentication | 6 (5) | SA-01, SA-02, SA-11, SA-12, SA-13 | SA-01, SA-02, SA-11, SA-13 | 80% |
| TW-NET2 | CORS allows any origin | 4 (4) | SA-07, SA-12, SA-34 | SA-07, SA-12, SA-34 | 100% |
| TW-NET4 | Unauthenticated route deletes data or spends the LLM key | 14 (9) | SA-01, SA-02, SA-11, SA-12, SA-15 | SA-01, SA-02, SA-11, SA-12, SA-15 | 100% |
| TW-NET5 | Server fetches a caller-controlled URL or path | 6 (3) | SA-01, SA-02, SA-11, SA-13, SA-22 | SA-01, SA-02, SA-11, SA-13, SA-22 | 100% |
| TW-OUT1 | Data written into HTML without escaping | 31 (19) | SA-16, SA-25, SA-32, SA-33, SA-35 | SA-25, SA-33, SA-35 | 60% |
| TW-OUT2 | CSV/Excel export without formula neutralisation | 11 (7) | SA-16 | - | 0% |
| TW-SEC1 | Credential committed to the repository (tree or git history) | 3 (2) | SA-03 | SA-03 | 100% |

Scanned 50 repos in 130.8s. Static rules catch **27/29** of the confirmed findings they target; those are 29 of all 44 confirmed findings. The rest (business logic, spec-to-code gaps, LLM output trust) are what the skill's method and `tripwire.fence` are for.
<!-- EVIDENCE:END -->

## Layout
`tripwire/` engine, rules and CLI · `tripwire/fence.py` runtime injection guard · `tests/` fixtures per rule ·
`docs/METHOD.md` the audit method · `docs/evidence/` per-rule hits on the real repos.
