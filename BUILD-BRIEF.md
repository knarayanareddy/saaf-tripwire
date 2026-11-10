# SAAF Tripwire — build brief (shared by all builder agents)

Hackathon task: "Build one guard that stops a bad actor. Find weaknesses in the SAAF agents, then turn
what you learn into a skill, a workflow or a CI check that any SAAF repository can reuse."
Our answer: ONE guard (working name **SAAF Tripwire**) = one deterministic Python engine + three thin
wrappers: a CI check (GitHub Action), a reusable workflow, and a Claude Code skill.

Workspace: `~/saaf-redteam/tripwire/`. **Do not run git commit / push, do not git init.** Do not modify
anything under `~/saaf-redteam/work/` or `~/saaf-redteam/run2/` (an audit is running there). Each agent writes
only the files it owns (listed in its prompt). The shared contract is `tripwire/model.py` + `tripwire/engine.py`
— do not change their shapes; if you need a helper, add it under `tripwire/util/` (create it if missing; check
first whether another agent already made one with the same name).

## Where the rules come from (evidence)
A confirmed, probe-backed audit of the 50 SAAF-Project repos is in `~/saaf-redteam/work/`:
`REPORT.md`, `FINDINGS-DETAIL.md`, `findings/findings.json` (44 confirmed + 40 rejected, each with file:line
traces and payloads), `NEEDS-VALIDATION.md`. Audited repos (read-only) are in `~/saaf-redteam/work/repos/`.
The method is `~/saaf-redteam/work/AGENT-PROMPT.md`. Every rule must cite which audit findings it would have
caught (`seen_in`) — that is our pitch: rules derived from real SAAF weaknesses, not a generic checklist.

## Rule quality bar (non-negotiable)
- Deterministic, offline, fast (whole repo < 10 s), no LLM calls.
- Each rule ships with fixtures in `tests/fixtures/<RULE_ID>/` — at least 2 `vulnerable_*` cases that MUST fire
  and 2 `safe_*` cases that MUST NOT — and a pytest in `tests/test_<rule_id>.py`. Cover the *template* of the bug,
  not just the one instance we saw (vary syntax: Flask vs FastAPI, single vs double quotes, etc.).
- Prove the detector fires on the real repos: run it against `~/saaf-redteam/work/repos/<repo>` for the repos in
  `seen_in` and record the hit in `docs/evidence/<RULE_ID>.md` (file:line hit, which SA-xx finding it matches).
  Also record false positives you see on 3 other repos and tighten the rule.
- Never print a secret: mask everything after 4 characters.
- Severity follows the audit rubric: localhost-only default caps at medium unless CORS/rebinding is shown.

## Output formats (owned by the CLI agent)
`tripwire scan <path> [--no-history] [--format text|json|sarif] [--fail-on high]` — exit 1 if any finding ≥ fail-on.
SARIF 2.1.0 so GitHub code scanning shows findings inline on PRs.
