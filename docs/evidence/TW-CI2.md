# TW-CI2 evidence — workflow injection & token scope

No SAAF repo currently expands `${{ github.event.* }}` into `run:`/github-script or uses `pull_request_target` with a head checkout — consistent with the audit (COVERAGE: saaf-guard "no ${{ github.event.* }} in run: → no workflow injection").

| Repo | Hit | Matches |
|---|---|---|
| Compliance-Report-Generator | .github/workflows/lint.yml:1 — no `permissions:` (low) | NEEDS-VALIDATION.md line 76 ("lint.yml declares no permissions") |
| demo-repository | .github/workflows/proof-html.yml:1 — no `permissions:` (low) | org sweep context of SA-24 |

True negatives on real repos:
- judging-found-controls ci.yml github-script interpolates only `needs.*.result` → silent (**SA-R36** rejected: confirmed not exploitable).
- Compliance-Report-Generator tests.yml:49 uses `github.event.pull_request.head.repo.full_name` in `with:` (not a script, and a repo name) → silent.
- SAAF-Project / Track-2 generate-dashboard.yml set permissions per job → silent.
The rule is preventive: fixtures cover PR title/head_ref in run:, issue body in github-script, pwn-request checkout, reusable workflow @main.
