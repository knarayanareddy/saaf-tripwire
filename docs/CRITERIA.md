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

## Sign-off recipe (not built in)

1. Run the criteria command in CI and keep `verdict.json` as an artifact.
2. Attest it (`actions/attest-build-provenance`, or cosign) so the verdict is bound to the commit and run.
3. Make the job a required status check and require a CODEOWNERS approval on the same change.

That gives a signed, auditable pass. The runner produces the evidence; the platform enforces the approval.

## Limits

- A rule criterion is only as good as the rule; a criterion with no rule must be a test or command.
- In the 50-repo evidence run, 27 of 29 in-scope findings were caught; findings outside the rule set can
  only be locked in by a repository-specific test.
- `test`/`command` checks inherit the runner's environment; a missing `pytest` is reported as an error,
  never as a pass.
