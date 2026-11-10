# TW-CI3 evidence — guard shadowed by a module in the scanned repo

| Repo | File:line | Matches |
|---|---|---|
| saaf-guard | .github/workflows/saaf-guard.yml:28 — `PYTHONPATH="$RUNNER_TEMP/saaf-guard" python -m saaf_guard.check . --history --fail-on high` (low) | **SA-41** |

Reasons the rule records: PYTHONPATH points outside the checkout; the tool is cloned outside the checkout (`git clone .../saaf-guard.git`); the workflow is `workflow_call` and runs its own `saaf_guard` package inside callers' checkouts.
Severity low (per SA-41: contents: read, no secrets); raised to medium if the workflow reads secrets.
Fix accepted by the rule: `python -P -m ...`, `python -I`, or `cd "$RUNNER_TEMP/..."` first.
False-positive check: Compliance-Report-Generator (`.venv/bin/python -m xmlrunner`), OWASP-AI-Testing-Agent (`python -m pytest`, `python -m pip_audit`), saaf-living-map (`python -m unittest`) — all silent (repo's own tests, no external tool on PYTHONPATH). 50-repo sweep: 1 hit.
Note for our own wrapper: the Tripwire CI action must itself run with `python -P` (or from outside the workspace).
