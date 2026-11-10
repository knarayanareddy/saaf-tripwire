# TW-DEP1 evidence — dependency hygiene (offline)

Offline only. The online advisory check (`pip-audit` / `npm audit --audit-level=critical`) is run by the CI wrapper, not by this rule. Severity capped at medium.

Hits in the repos the audit's COVERAGE.md marked "deps unpinned" (no SA id — coverage notes):
| Repo | Hit |
|---|---|
| Team-HighTable | backend/requirements.txt:1 — 7 unpinned (fastapi, uvicorn…), FastAPI app, no lock (medium) |
| Finding-analysis | requirements.txt:1 — 12 unpinned (flask…), no lock (medium) |
| PBC-Assistant-Isabelle---IA-AI-Hackathon | requirements.txt:1 — 7 unpinned (medium) |
| FieldworkOrchestration | requirements.txt:1 — 10 unpinned (medium) |
| saaf-living-map | .github/workflows/build-map.yml:26, :40 — `pip install pyyaml` (low) |
| OWASP-AI-Testing-Agent | .github/workflows/ci.yml:36 — `pip install pip-audit cyclonedx-bom` (low) |
Also: Agent-Auditor server/, Executive-Summary-Writer (2), Track-2---IAM-final tools/scripts/bart, joiners-movers-leavers-agent.
True negative: Track-4-Audit-Report-Generator (requirements pinned ==) → silent.

False positives fixed:
1. judging-found-controls ci.yml:108 — text "`pip install -r requirements.txt`" inside an actions/github-script report → github-script steps skipped.
2. agent-drift-rater sample_data/…/package.json → sample/fixture/test paths skipped.
3. SAAF-Project / Track-2 monorepos flagged every requirements file (audio, track-5…) because some other folder served HTTP → only the requirements file in the server's own folder (or a plain requirements.txt in a parent) counts.
