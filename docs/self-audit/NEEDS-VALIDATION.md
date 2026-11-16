# Needs validation

Not findings. Each row is one thing this audit could not settle, why it matters, and the check that would settle it. No severity is assigned.

| ID | Component | Question | Exact unresolved fact |
|---|---|---|---|
| TW-N1 | tripwire/deps.py | The optional online audit (pip-audit / npm audit) runs against auditee manifests. A repo could point pip at an attacker index or inject requirements options (--index-url, -r, config) that make the CI runner fetch attacker metadata. | No test exercises deps.py with a hostile requirements.txt; need to check whether it passes --index-url through or lets pip read .pip/pip.conf from the audited checkout. |
| TW-N2 | rules/sec_secrets.py history scan | A multi-GB or deeply packed history may exhaust memory before the timeout fires. The timeout now fails closed, so this is availability only, but peak RSS is unmeasured. | No large-object or very long-history repo was built; RSS and the timeout path under memory pressure are unverified. |
| TW-N3 | tripwire/fence.py + check_quotes | Fence/quote checks were measured to 4 MB, not against the 100 MB documents an adversarial repo could ship. | Measure 50–100 MB inputs end to end; MAX_BYTES (8 MB) bounds file reads, but a document passed directly to fence() is not capped. |

The audit's stop condition does not require these to be closed, but the gate must not pretend they are covered: `coverage-ledger.json` marks their units `covered` only in the sense that the question was raised, and the record stays `needs_validation`.
