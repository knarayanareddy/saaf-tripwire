# TW-SEC1 evidence — secrets in tree and reachable git history

Run: `engine.run(repo, only={"TW-SEC1"})` (history on) against `~/saaf-redteam/work/repos/*` (read-only), 2026-11-10.
Values are never printed: only the first 4 chars, the length and the provider class.

| Repo | Hit | Severity | Matches |
|---|---|---|---|
| Team-HighTable | `backend/.env` @ **1294181** — anthropic key `sk-a… (len 108)` | high (history) | **SA-03** |
| Team-HighTable | `backend/.env` @ 1294181 — TEAMMATE key `P6ja… (len 44)`, high entropy | high | SA-03 |
| Team-HighTable | `backend/.env` @ 1294181 — BACKEND key `Tx6#… (len 12)` | high | SA-03 |
| ExecGRC | `.env.example` @ **22177ad** — anthropic key `sk-a… (len 108)`, entropy 5.5 bits/char, 51 distinct chars, no placeholder words; file deleted in 5a80ff3 but still reachable | high (history) | **new — not in the audit** (audit only checked the tree) |

## Commits the brief asked us to check
- **Team-HighTable 1294181** — fires (3 values). Removed from tree in ea1d1ec; still in history.
- **ExecGRC 22177ad** — fires: a full-length, high-entropy Anthropic-format key in `.env.example`. Real-key shape; recommend rotation. Audit missed it.
- **SAAF-Project 29968a2 / caabf5d** — do NOT fire. Both add `.claude/skills/harden-agent-repo/SKILL.md`, which lists the patterns `sk-`, `AKIA`, `` `-----BEGIN PRIVATE KEY-----` `` as prose. First version of the rule fired *critical* on the private-key header (false positive, fixed: header must stand alone on its line or be followed by base64 data).
- **saaf-portal 7b5eafd** — does not fire. `.env.local.example` holds `"gene… (len 36)"` (a "generate-…" instruction), `"..."` and `"gith… (len 14)"` (a `github_pat_...`-style stub) — all placeholders.

## Audit rejections that stay silent (true negatives)
SA-R08 Executive-Summary-Writer (test-marked spec), SA-R25 Stress-test (synthetic alphabet fixture), SA-R32 fraude-risicoanalyse-podcast, SA-R34 hallucination-detection-agent: 0 findings.

## False positives found and fixed (50-repo sweep)
1. SAAF-Project SKILL.md private-key header in prose → critical FP; fixed (see above).
2. Finding-analysis `.env.example` `FLASK_SECRET_KEY=vera… (len 35)` = Dutch placeholder "change this to something random" (passed entropy) → fixed with a word-sequence filter; regression line added to `safe_placeholders`.
Final sweep: 4 hits, all in Team-HighTable and ExecGRC. Speed: a prefilter keeps the largest history (SAAF-Project, 10 MB of diffs) under 5 s.
