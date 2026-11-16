# Self-audit report — SAAF Tripwire

**Target** `saaf-tripwire` @ `281bbcd + working tree fixes (2026-11-16)` · **Method** cloudflare/security-audit-skill 6-phase workflow + spec-to-code / sharp-edges / variant analysis · **Date** 2026-11-16

## Verdict

The guard's *detection* logic holds up; its *delivery* and *evidence integrity* did not. 9 confirmed defects (4 high, 3 medium, 2 low), all 9 now fixed or mitigated (8 fixed, 1 mitigated); 5 candidates disproved; 3 facts still unresolved. The most serious are not in the rules: a hostile repo could execute code through git (`textconv`, `core.fsmonitor`), and the shipped action could not start at all because its only runtime dependency was undeclared and `--no-deps` skipped it.

This audit also demonstrates the repo's missing phase-4/5 machinery: `findings.json` is schema-validated and every record re-probed by `probes/`, but that machinery lives in this audit directory, **not in the product** (R-08 still stands).

## Confirmed

| ID | Severity | Class | Status | Component | Finding |
|---|---|---|---|---|---|
| TW-A1 | high | `web-protocol-and-auth` | fixed | rules/sec_secrets.py history scan | A committed .gitattributes can name a textconv driver, and `git log -p` executes it while scanning history. `--no-ext-diff` does not stop textconv, so the audited repo runs code as the CI user. |
| TW-A2 | high | `web-protocol-and-auth` | fixed | engine.tracked_files | `core.fsmonitor` in the audited repo's config is executed by `git ls-files`, so every scan runs auditee code — including scans that explicitly skip history. |
| TW-A3 | high | `business-logic` | fixed | rules/sec_secrets.py history scan | Any git failure (dubious ownership, timeout, kill) was swallowed, so the history rule reported zero findings with no error: a broken audit looked like a clean audit. |
| TW-A8 | high | `supply-chain-and-release` | fixed | action.yml + pyproject.toml | PyYAML is imported by gha.py but was not a declared dependency, and the action installed with --no-deps. On a clean runner every scan died with ModuleNotFoundError, so the shipped gate could not run at all. |
| TW-A4 | medium | `business-logic` | fixed | rules/sec_secrets.py history scan | On a shallow clone (the default actions/checkout depth is 1) the history rule reported a clean result even though the key lived in a commit outside the clone. |
| TW-A5 | medium | `client-side` | fixed | report text and SARIF | A tracked filename containing a newline produced a report line that began with `::error::`, i.e. an auditee could forge a GitHub workflow command (annotation) in the CI log. |
| TW-A6 | medium | `ai-and-llm` | mitigated | skill/saaf-tripwire + report evidence | Finding evidence and messages carry auditee text verbatim into the consuming agent, so the repo can address the model directly (prompt injection). This is an output-contract property, not a parser bug. |
| TW-A7 | low | `supply-chain-and-release` | fixed | action.yml install step | The action installed the guard with a PEP 517 build, which fetched an unpinned setuptools from the package index at run time — even with --no-index the build failed. |
| TW-A9 | low | `quality` | fixed | rules/dep_hygiene.py | TW-DEP1 matched `pip install` inside shell comments and treated a trailing backslash as an unpinned package, so the fixed action produced two false low findings on its own scanner. |

## Disproved candidates

| ID | Class | Candidate | What killed it |
|---|---|---|---|
| TW-R1 | `resource-exhaustion` | Candidate: catastrophic backtracking in a rule regex on pathological auditee input. | 16 rules over 5 files completed in 379 ms; no single rule over 0.2 s; 4 MB neutralise 0.82 s, check_quotes 0.35 s (linear). |
| TW-R2 | `ai-and-llm` | Candidate: an auditee document can close the fence early and escape neutralisation. | 30+ payloads (nested fences, uppercase, zero-width, HTML comments, markdown headings) leave no `<`, `>`, or fence marker in the neutralised body. |
| TW-R3 | `data-isolation` | Candidate: a tracked symlink or parent-repo path makes the scanner read outside the scanned root. | tests/test_symlink_safety.py: /etc/passwd target and /dev/zero are refused by realpath containment and S_ISREG; no bytes cross the boundary. |
| TW-R4 | `client-side` | Candidate: an auditee filename injects a second SARIF result or breaks the JSON document. | newline/quote/C1 filename: output parses as JSON, one result, uri is a single escaped string (control chars removed by _safe). |
| TW-R5 | `business-logic` | Candidate: an auditee file crashes one rule and hides the rest of the findings. | rule errors are recorded and force exit 2 (fail closed); findings from the other 15 rules are still emitted, so a crash cannot be used to pass the gate. |

## Coverage

15/18 ledger units covered by an executed check; 3 out of scope with a named reason (see `coverage-ledger.json`, validated by `validate.py`).

| Unit | Surface | Status | Result / reason |
|---|---|---|---|
| U01 | CLI scan over a worktree | covered | regular files only; symlink/device/size guards hold (R-09) |
| U02 | git ls-files on an untrusted repo | covered | confirmed TW-A2, fixed: no execution |
| U03 | git log -p on an untrusted repo | covered | confirmed TW-A1, fixed: --no-textconv |
| U04 | history scan failure modes | covered | confirmed TW-A3/A4, fixed: fail closed (exit 2) |
| U05 | tracked filenames rendered into text/SARIF | covered | confirmed TW-A5, fixed: control chars collapsed |
| U06 | finding text into GitHub CI logs (workflow commands) | covered | covered by the same control-char normalisation |
| U07 | symlinks, devices, huge files | covered | rejected candidates: /etc/passwd read and /dev/zero OOM are blocked (R-09) |
| U08 | in-repo control plane (.tripwireignore, baseline) | covered | fixed in docs/REVIEW (R-01/R-02); in-action override still enforced |
| U09 | scan output consumed by an agent | covered | TW-A6 mitigated: data is fenced, SKILL.md declares output untrusted |
| U10 | action build/install supply chain | covered | confirmed TW-A7/A8, fixed: no PEP 517 build, PyYAML pinned |
| U11 | workflow/action permissions and pinning | covered | least privilege, SHA pins, base ref validated |
| U12 | rule accuracy on its own configuration | covered | confirmed TW-A9 (false positives), fixed |
| U13 | optional online dependency audit | covered | candidate TW-N1 recorded in NEEDS-VALIDATION |
| U14 | history scan memory footprint | covered | candidate TW-N2 recorded in NEEDS-VALIDATION |
| U15 | fence library (neutralisation, quotes, size) | covered | no bypass found; performance linear |
| U16 | README/HOW-IT-WORKS/pitch claims vs evidence | out_of_scope | documentation claims audit, already reported in docs/REVIEW-2026-11-16.md §6; not a code trust boundary |
| U17 | OS-level containment of probes | out_of_scope | no sandbox available; probes run as the invoking user against throwaway repos under mktemp, and no probe writes outside them |
| U18 | Windows/macOS path and git semantics | out_of_scope | verified on Linux only; the action targets ubuntu runners |

## Still unresolved

See `NEEDS-VALIDATION.md` — TW-N1, TW-N2, TW-N3.

## Sharp edges worth knowing (not defects)

- **A shallow checkout now refuses to scan history.** `actions/checkout` defaults to depth 1; callers must set `fetch-depth: 0` or pass `history: false`. This is the intended fail-closed behaviour, but it is a breaking change for anyone who relied on the old silent zero.
- **Finding evidence is auditee text.** It reaches the consuming model verbatim. The skill now declares it untrusted and requires `fence()`; any other consumer must do the same.
- **`--no-history` is an explicit coverage hole.** It is the documented escape hatch for shallow clones; it must never be the CI default.
- **PyYAML is version-pinned, not hash-pinned.** The action still fetches one wheel from the index at run time; a `--require-hashes` requirements file is the next step if the runner must be index-independent.

## Reproduce

```sh
python docs/self-audit/validate.py          # schema + ledger constraints
python docs/self-audit/render.py            # regenerate this report
python docs/self-audit/probes/probes.py     # 14/14 probes
python -m pytest -q                         # 287 tests
```
