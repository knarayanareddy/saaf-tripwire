# The SAAF audit method (for humans)

SAAF Tripwire's rules come from a probe-backed audit of all 50 SAAF-Project repositories
(44 confirmed findings, 40 rejected candidates, 114 deterministic probes, 44 of 44 fixes flipped in a staging tree).
This is the method that produced them, condensed. The full prompt is `AGENT-PROMPT.md` in the audit workspace.

## The one rule
**Every finding is executed, not inferred.** A claim you could not run is a rejected candidate with the reason
written down, or an item in NEEDS-VALIDATION. It is never a finding.

## Phases
1. **Recon.** List entrypoints mechanically (HTTP routes, CLI entrypoints, public library functions, scheduled
   jobs, CI workflows, files that ingest untrusted artefacts) and count them per repo. Pin every repo by commit
   SHA. Never modify an audited repo: patches live in a staged copy.
2. **Coverage ledger.** A coverage unit is `surface x trust boundary x subsystem x attack class`. Each unit ends
   `covered` (an owning check and its one-line result) or `out_of_scope` (an honest, named reason: needs a GPU,
   a browser, live cloud credentials, dead code). There is no third status.
3. **Attack-class hunt.** Six classes: AI and LLM, web protocol and auth, client-side, data isolation, resource
   exhaustion and business logic, supply chain and release. Start with the least-covered repos. For every
   untrusted value that crosses a boundary, record the trace: source -> propagation (file:line) -> sink.
4. **Lenses on every repo.**
   - *Spec-to-code:* turn each stated control into a test ("every quote is checked verbatim", "PO, GRN and invoice
     amounts agree"). The best findings are mechanisms that exist but are not wired in.
   - *Sharp edges:* APIs that invite the next bug (a guard that is a pure predicate over one call, auth
     reimplemented per route, a helper that both authorises and mutates).
   - *Variant analysis:* when you find a pattern once, sweep the org and report the count.
5. **Probe.** A deterministic, offline probe must fail on the current tree, pass on the patched staging tree, and
   give the same verdict twice. It resolves the tree through an environment variable, so the patched run really
   tests the patched tree. It drives the entrypoint the attacker reaches (the route, the dispatcher), never a
   helper beside it, and imports real defaults from the code.
6. **Independent disproof.** A verifier that never saw the hunt tries to kill each candidate. Survivors are
   confirmed. The rest are recorded as rejected with the payload that refuted them. Zero rejections means this
   phase was skipped.
7. **Report honestly.** Severity is reasoned from likelihood, impact and confidence, each with a reason.
   A localhost-only service caps at medium unless CORS or DNS rebinding is shown. "Fixes validated in staging"
   and "remediation progress" are different numbers. Report the counts you got, including zeros and skipped repos.

## Lessons from the SAAF run
- **Time-box honestly.** The run was ~75 minutes; 34 reproduced candidates were not finished by a verifier and
  were reported only in NEEDS-VALIDATION, not as findings.
- **Never confirm what you did not check.** Where a verifier did not run its own variant payload, the finding is
  marked provisional.
- **Probe the entrypoint, not a helper.** Probing a predicate beside the route produced false negatives.
- **One patch that fixes the probe's payload is not a fix** (SA-R33): re-test with variants.
- **Upstream defaults are baselines**, not repo defects.

## Where Tripwire fits
Run `tripwire scan` first: it catches the repeatable patterns (network exposure, CORS, committed secrets, CI
supply chain) in seconds, on every push. Spend human and agent time on what rules cannot see: fail-open
business logic, spec-to-code gaps, and LLM trust boundaries, where `tripwire.fence` and `check_quotes` are the
runtime guard.
