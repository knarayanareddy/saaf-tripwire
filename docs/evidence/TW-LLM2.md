# TW-LLM2 evidence

Run: `engine.run(~/saaf-redteam/work/repos/<repo>, history=False, only={'TW-LLM2'})` (read-only).

## Hits on audited repos

| Repo | Hit | Audit finding |
|---|---|---|
| judging-found-controls | agent.py:136 `return verdict` (only key presence checked); :116 no quote check for `paragraph` | SA-20 (trace agent.py:132-133) |
| hallucination-detection-agent | hallucination/verifier.py:31 SUPPORTED accepted with no quote check | SA-R33 |
| SAAF-Project | track-5/hallucination/verifier.py:31 (same); frank-lubbers-...-azure-devops.py:80/:137 model `priority` overrides rating | SA-14 chain / SA-31 (trace line 137) |
| Compliance-Report-Generator | saaf/core/agent.py:237 `ComplianceReport(**data)` - model-supplied report_id accepted | Compliance-Report-Generator__E2 (needs-validation) |
| Vendor_Guard | agents/orchestrator.py:33 `VendorProfile(**data)` - model booleans route frameworks | Vendor_Guard__A1 (needs-validation) |

## Notes, false positives and limits

False-positive review: APM-Writer 0, FieldworkOrchestration 0, Executive-Summary-Writer 0 (after treating a pydantic class argument
as schema validation), Policy-to-Controls-Extractor 2 (heading-detection JSON returned unvalidated - low-impact, not a verdict;
documented FP). SAAF-Project access_review_app.py / work_program_generator.py / llm-owasp auditor.py: unvalidated model fields,
plausible TPs not in the audit. demo/guarded_auditor.py (the fixed demo) is silent: check_quotes() counts as validation.
Known limits: one level of local-function summaries; validation is recognised by allowlist membership tests, check_quotes /
validate*/verify*/ground* calls and pydantic model_validate - a validator that exists but is not called on the value is not seen.

## Raw run output

```
== judging-found-controls: 3 (0.1s)
  agent.py:116 [high] Unvalidated model output: verdicts that cite quotes/evidence (paragraph) are accepted with no check that the quoted text occurs in the source. || def judge_control(
  agent.py:136 [high] Unvalidated model output: parsed model output is returned as the verdict with no value check. || return verdict
  agent.py:163 [high] Unvalidated model output: model-supplied 'found' is used without an allowlist/grounding check. || print(f"found={verdict['found']}")
== hallucination-detection-agent: 1 (0.1s)
  hallucination/verifier.py:31 [high] Unvalidated model output: verdicts that cite quotes/evidence (SUPPORTED) are accepted with no check that the quoted text occurs in the source. || def verify_claims(claims: list[Claim], rag_context: str) -> list[ClaimVerdict]:
== Compliance-Report-Generator: 1 (0.7s)
  saaf/core/agent.py:237 [high] Unvalidated model output: model JSON is splatted wholesale into ComplianceReport(**...): every field, including ones the agent should own, is model-co || report = ComplianceReport(**data)
== Vendor_Guard: 1 (0.3s)
  agents/orchestrator.py:33 [high] Unvalidated model output: model JSON is splatted wholesale into VendorProfile(**...): every field, including ones the agent should own, is model-contr || return VendorProfile(**data)
== SAAF-Project: 7 (1.2s)
  tools/scripts/access_review_app.py:227 [high] Unvalidated model output: parsed model output is returned as the verdict with no value check. || return findings
  tools/scripts/access_review_app.py:383 [high] Unvalidated model output: model-supplied 'risk_rating' is used without an allowlist/grounding check. || risk = finding.get("risk_rating", "")
  tools/scripts/frank-lubbers-ai-finding-escalation-azure-devops.py:80 [high] Unvalidated model output: parsed model output is returned as the verdict with no value check. || return json.loads(text.strip())
  tools/scripts/frank-lubbers-ai-finding-escalation-azure-devops.py:137 [high] Unvalidated model output: model-supplied 'priority' is used without an allowlist/grounding check. || priority = enriched.get("priority") or RISK_TO_PRIORITY.get(finding.get("risk_rating", "Lo
  tools/scripts/llm-owasp/owasp_llm_audit/auditor.py:96 [high] Unvalidated model output: model-supplied 'verdict' is used without an allowlist/grounding check. || verdict=data.get("verdict", "N-A"),
  tools/scripts/track-5/hallucination/verifier.py:31 [high] Unvalidated model output: verdicts that cite quotes/evidence (SUPPORTED) are accepted with no check that the quoted text occurs in the source. || def verify_claims(claims: list[Claim], rag_context: str) -> list[ClaimVerdict]:
  tools/scripts/work_program_generator.py:107 [high] Unvalidated model output: parsed model output is returned as the verdict with no value check. || return json.loads(text)
== APM-Writer: 0 (0.0s)
== Executive-Summary-Writer: 0 (0.7s)
== FieldworkOrchestration: 0 (0.5s)
== Policy-to-Controls-Extractor: 1 (0.2s)
  services/segments.py:71 [high] Unvalidated model output: parsed model output is returned as the verdict with no value check. || return result
```
