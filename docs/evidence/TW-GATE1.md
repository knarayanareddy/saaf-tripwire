# TW-GATE1 evidence

Run: `engine.run(~/saaf-redteam/work/repos/<repo>, history=False, only={'TW-GATE1'})` (read-only).

## Hits on audited repos

| Repo | Hit | Audit finding |
|---|---|---|
| threewaysecurity | src/agent/decision_agent.py:89 else -> APPROVE | SA-04 (trace decision_agent.py:89) |
| threewaysecurity | src/security/secure_pipeline.py:116 schema except only logs/counts; :130 PDF reject only logs | SA-05 (trace secure_pipeline.py:121) |
| Audit-criteria | tools/scripts/audit_criteria_orchestrator/schemas.py:150 `r["ac"] not in deviations` | SA-08 (trace schemas.py:150) |
| three-way-match-audit | webapp/app/services/matcher.py:180 abs(..) > tol with no NaN guard; :338 rollup default MATCH | SA-23 (trace matcher.py:180) |
| SAAF-Project / hallucination-detection-agent | track-5/hallucination/aggregator.py:53 else -> LOW | SA-14 (trace aggregator.py:48/79) |
| CUEC_Crosscheck | cuec_crosscheck.py:555/:571 completeness check SKIPPED/FAILED only logs; :289 `_compute_rag` defaults Green | brief evidence (CUEC completeness) |

## Notes, false positives and limits

False-positive review: Executive-Summary-Writer 0, FieldworkOrchestration 0, Vendor_Guard 0 (count-based RAG thresholds are excluded),
saaf-guard 2 (demo/bad_agent - intentional). Remaining noise: SAAF-Project generate_dashboard.py:746 (a warning that an alert is
skipped on shallow clones - medium, arguably informational); CUEC :193 (max_tokens truncation only warned - arguably real).
Removed: threewaysecurity gen_labels.py (synthetic-data generator dirs are skipped); pandas isna guards; try/except/else imports.
Red-team (redteam/RESULTS.md): 6/7 evasions + 2/2 FPs before -> 0/7 evaded, 0/2 FP after (or-default, getattr default, dict
default with variable key, match/case _, abs() via a temp var, .lower() substring, except that logs and still approves).
Known limits: default-allow is recognised from string verdict literals (APPROVE/PASS/Green/MATCH/LOW...); enum members or booleans
(`approved = True`) are not; numeric threshold classifiers are intentionally ignored.

## Raw run output

```
== threewaysecurity: 3 (0.2s)
  src/agent/decision_agent.py:89 [high] Fail-open: decision chain blocks only on listed states; anything else (unknown, SKIP, missing) falls to the else branch -> 'APPROVE'. || decision = "APPROVE"
  src/security/secure_pipeline.py:116 [high] Fail-open: gate failure in run_pre_intake_security() is caught and only logged/counted; processing continues as if it passed. || except Exception as e:
  src/security/secure_pipeline.py:130 [medium] Fail-open: failure branch only logs: 'PDF_REJECTED HIGH pdf_rejected PDF safety check failed:'. || self.security_log.log_event(
== CUEC_Crosscheck: 6 (0.1s)
  cuec_crosscheck.py:143 [medium] Fail-open: failure branch only logs: 'Pre-check: could not parse CUEC ID list from response — comp'. || logger.warning("Pre-check: could not parse CUEC ID list from response — completeness check
  cuec_crosscheck.py:193 [medium] Fail-open: failure branch only logs: 'Response was cut off at max_tokens={} — output may be incomp'. || logger.warning(
  cuec_crosscheck.py:289 [high] Fail-open: _compute_rag() returns 'Green' by default once the listed failure checks miss - empty or unknown input passes. || return "Green"
  cuec_crosscheck.py:555 [medium] Fail-open: failure branch only logs: 'Completeness check SKIPPED — pre-check returned no CUEC IDs'. || logger.warning("Completeness check SKIPPED — pre-check returned no CUEC IDs")
  cuec_crosscheck.py:571 [medium] Fail-open: failure branch only logs: 'CUECs present in vendor report but missing from output: {}'. || logger.error("CUECs present in vendor report but missing from output: {}", missing)
  cuec_crosscheck.py:573 [medium] Fail-open: failure branch only logs: 'CUECs in output not found in pre-check inventory: {}'. || logger.warning("CUECs in output not found in pre-check inventory: {}", extra)
== three-way-match-audit: 2 (0.1s)
  webapp/app/services/matcher.py:180 [high] Fail-open: 7 tolerance check(s) like 'abs(a-b) > tol' with no NaN/inf guard: a NaN amount makes every check false and the record matches. || if abs(disc) > total_tolerance:
  webapp/app/services/matcher.py:338 [high] Fail-open: _rollup() returns 'MATCH' by default once the listed failure checks miss - empty or unknown input passes. || return "MATCH"
== Audit-criteria: 1 (0.4s)
  tools/scripts/audit_criteria_orchestrator/schemas.py:150 [high] Fail-open: identifier 'ac' is matched as a substring of 'deviations' ('AC-1' is found inside 'AC-10'). || elif r["outcome"] == "fail" and r["ac"] not in deviations:
== SAAF-Project: 3 (1.1s)
  tools/scripts/frank-lubbers-ai-finding-escalation-azure-devops.py:137 [medium] Fail-open: missing/unknown 'risk_rating' defaults to passing value 'Low'. || priority = enriched.get("priority") or RISK_TO_PRIORITY.get(finding.get("risk_rating", "Lo
  tools/scripts/generate_dashboard.py:746 [medium] Fail-open: failure branch only logs: 'Shallow git clone: plan file ages are unknown, so the 'PDCA '. || log.warning("Shallow git clone: plan file ages are unknown, so the 'PDCA not updated' aler
  tools/scripts/track-5/hallucination/aggregator.py:53 [high] Fail-open: decision chain blocks only on listed states; anything else (unknown, SKIP, missing) falls to the else branch -> 'LOW'. || risk = "LOW"
== hallucination-detection-agent: 1 (0.1s)
  hallucination/aggregator.py:53 [high] Fail-open: decision chain blocks only on listed states; anything else (unknown, SKIP, missing) falls to the else branch -> 'LOW'. || risk = "LOW"
== saaf-guard: 2 (0.2s)
  demo/bad_agent/agent.py:18 [high] Fail-open: rag() returns 'Green' by default once the listed failure checks miss - empty or unknown input passes. || return "Green"
  demo/bad_agent/agent.py:22 [high] Fail-open: 1 tolerance check(s) like 'abs(a-b) > tol' with no NaN/inf guard: a NaN amount makes every check false and the record matches. || if abs(a - b) > tol:
== Executive-Summary-Writer: 0 (0.9s)
== FieldworkOrchestration: 0 (0.3s)
== Vendor_Guard: 0 (0.2s)
```
