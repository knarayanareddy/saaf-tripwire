# Criteria: per-agent pass/fail

`tripwire scan` answers *does this repository contain a known-bad pattern*. A criteria manifest answers
*does this agent meet each audit criterion*, and turns the answer into data a gate can consume.

## Manifest

```yaml
# .tripwire/criteria.yml
version: 1
agent: my-agent
criteria:
  - id: SA-39
    title: Model output is validated before it is acted on
    check: {rule: TW-LLM1}
  - id: authz
    title: Every route requires authentication
    check: {test: "tests/test_authz.py::test_every_route_requires_auth"}
  - id: audit-log
    title: State-changing routes emit an audit log line
    check: {command: "python scripts/check_audit_log.py"}
```

- `check.rule` — run one Tripwire rule. Read-only; honours `.tripwireignore` and `--baseline`, so the
  verdict matches the scan gate.
- `check.test` — run one pytest node with the interpreter running the guard. Needs the repository's test
  dependencies installed.
- `check.command` — run a command in the repository root (`shlex`, no shell). Exit 0 is pass.

The manifest is validated before anything runs: version 1, non-empty `criteria`, unique ids matching
`[A-Za-z0-9][A-Za-z0-9._:-]{0,63}`, exactly one check per criterion, and the file must resolve inside the
scanned root.

## Trust model

`rule` checks only read the tree. `test`/`command` checks execute code from the scanned tree, so they are
refused unless the caller opts in:

- CLI: `--allow-exec`
- action: `criteria-exec: true`

The action defaults to `false` and never turns it on implicitly. Enable it only when running code from the
scanned tree is already part of the job (for example, the repository's own test suite).

## Verdict

```json
{
  "tool": "saaf-tripwire",
  "version": "0.1.0",
  "agent": "my-agent",
  "commit": "…",
  "criteria": [{"id": "SA-39", "check": {"rule": "TW-LLM1"}, "status": "pass", "detail": "0 findings"}],
  "summary": {"total": 1, "pass": 1, "fail": 0, "error": 0},
  "verdict": "pass"
}
```

Exit codes match `scan`: **0** all pass, **1** any fail, **2** guard error (bad manifest, unknown rule, a
check that could not run, execution refused). No timestamp is included, so the same commit and manifest
produce the same file.

## Sign-off: what is built, and what only you can do

The runner produces evidence; the platform enforces approval. Three layers, in that order:

**1. Keep the verdict (built).** The action exposes the verdict's path as the `verdict` output, and the
reusable workflow always uploads it as the `saaf-tripwire-verdict` artifact (30-day retention). The step
runs `if: always()`, so a **failing** verdict is retained too — the artifact is evidence of a fail, not a
trophy for a pass. The criteria step inside the action never fails the job by itself: the final `Gate` step
does, after the verdict file exists, so there is no path where a "no" returns before the evidence is kept.

```yaml
- uses: actions/download-artifact@<sha> # v8
  with: {name: saaf-tripwire-verdict, path: verdict}
```

**2. Attest it (built here, opt-in for you).** `.github/workflows/self-scan.yml` has a `sign` job that
attests the downloaded verdict with `actions/attest-build-provenance`, binding it to this commit and this
workflow run:

```bash
gh attestation verify verdict/tripwire-verdict.json -R <owner>/<repo>
```

It is a **separate caller-side job**, not a step inside the reusable workflow, for a hard reason:
attesting needs `id-token: write` and `attestations: write`, and GitHub rejects the entire run at startup
if a called job requests a scope its caller did not grant. Putting it in the shared workflow would break
every consumer that has not updated its permissions in the same release. Copy the `sign` job into your own
workflow and grant those two scopes there.

Two constraints worth knowing before you adopt it:

- **Private repos need Enterprise Cloud** for artifact attestations. On Team/Free the attestation step
  fails; keep the artifact and skip signing there.
- **Signing is not a scan.** It proves *this verdict came from this commit in this run*. It does not prove
  the verdict was pass, or that the manifest was honest — a caller can set `criteria-exec: false` and
  still get a signed verdict full of `error` entries.

**3. Require it (not applied — a repo setting).** Make the checks required on `main` and require a
CODEOWNERS review on the manifest and workflow. Expected check names from this repository's setup:

- `tests`
- `self-scan / SAAF Tripwire`
- `sign` (only if you attest)

This has **not** been applied, and cannot be from inside the repository: the automation token used here
gets `403 Resource not accessible by integration` on the branch-protection API. A repository admin must
enable it under *Settings → Branches → Protect `main` → Require status checks to pass*. Record which
checks you actually required; a doc that claims enforcement it does not have is worse than no doc.

## Limits

- A rule criterion is only as good as the rule; a criterion with no rule must be a test or command.
- In the 50-repo evidence run, 27 of 29 in-scope findings were caught; findings outside the rule set can
  only be locked in by a repository-specific test.
- `test`/`command` checks inherit the runner's environment; a missing `pytest` is reported as an error,
  never as a pass.
