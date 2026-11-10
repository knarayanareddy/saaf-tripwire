# TW-CI1 evidence — actions not pinned to a commit SHA

All 5 references of **SA-24** fire (low; no non-GITHUB_TOKEN secrets in those workflows → not raised to medium):

| Repo | File:line | Ref |
|---|---|---|
| Compliance-Report-Generator | .github/workflows/lint.yml:13 | astral-sh/ruff-action@v3 |
| Compliance-Report-Generator | .github/workflows/tests.yml:45 | EnricoMi/publish-unit-test-result-action@v2 |
| agent-rogue-risk-assessor | .github/workflows/release.yml:22 | softprops/action-gh-release@v2 |
| demo-repository | .github/workflows/auto-assign.yml:15 | pozil/auto-assign-issue@v1 |
| demo-repository | .github/workflows/proof-html.yml:9 | anishathalye/proof-html@v1.1.0 |

Extra: saaf-guard `.github/workflows/saaf-guard.yml:25` — `git clone --depth 1` of the guard at `main` (low), the "guard clone is also unpinned" note in **SA-41**.

First-party `actions/*` / `github/*` tags are reported as **info** only (matches SA-R36 judging-found-controls verdict "first-party only, informational").
False-positive check on other repos (judging-found-controls, saaf-living-map, OWASP-AI-Testing-Agent, SAAF-Project, Track-2---IAM-final): only info-level first-party hits. 50-repo sweep: exactly 6 non-info hits, all above.
