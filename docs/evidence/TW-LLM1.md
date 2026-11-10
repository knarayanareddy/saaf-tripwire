# TW-LLM1 evidence

Run: `engine.run(~/saaf-redteam/work/repos/<repo>, history=False, only={'TW-LLM1'})` (read-only).

## Hits on audited repos

| Repo | Hit | Audit finding |
|---|---|---|
| llm_owasp | owasp_llm_audit/collector.py:67 (fixed ``` fence), auditor.py:200 (material into messages.create) | SA-39 (trace collector.py:67 -> auditor.py:218) |
| OWASP-AI-Testing-Agent | owasp_ai_testing_agent/sanitise.py:13 (neutraliser misses `</untrusted_input x>`) | SA-30 (trace sanitise.py:42 uses this _TAG_RE) |
| Track-2-Evidence-Collection-Extraction | compliance_qa.py:271 `<document>` and :266 `<additional_context>` static tags | SA-R27 (rejected on the quote leg; the delimiter forging itself is real) |
| CUEC_Crosscheck | cuec_crosscheck.py:109, :159 vendor report spliced into both prompts | brief evidence (no SA id; CUEC completeness is SA-adjacent) |
| joiners-movers-leavers-agent | ai/claude_runner.py:139 render_user_prompt splices ticket payload (claude -p) | SA-38 (trace claude_runner.py:135) |
| Vendor_Guard | agents/*.py vendor_docs in 6 prompts | Vendor_Guard__A1 (needs-validation) |
| judging-found-controls / hallucination-detection-agent | agent.py:122; extractor.py:44, verifier.py:100 | SA-20 / SA-R33 traces (policy/finding text into prompt) |

## Notes, false positives and limits

False-positive review (unrelated repos): APM-Writer 0, ExecGRC 0, GDPR-AI-Audit-Agent 0, RCM-Builder 0, FieldworkOrchestration 0 (after
restricting prompt-builder names; `text_from_message()` was a FP), Executive-Summary-Writer 1 (scripts/llm_openai.py:81: a `text`
argument into the prompt - plausible TP, the caller passes audit material), Policy-to-Controls-Extractor 3 (policy text into the
prompt unfenced - true positives, not in the audit). saaf-guard demo/bad_agent is an intentionally bad demo (TP).
Removed noise: HTML report f-strings (`<td>{x}</td>`) no longer count as static delimiters.
Known limits: name-based taint (vocab of document/text/ticket/...); one level of wrapper functions; JS/TS is regex-only
(template literals near an SDK call); html.escape/sanitise() deliberately do NOT count as a fence.

## Raw run output

```
== llm_owasp: 3 (0.2s)
  owasp_llm_audit/auditor.py:200 [high] Untrusted text is spliced into the prompt sent by client.messages.create() at line 218 without a fence. || user_prompt = f"""\
  owasp_llm_audit/collector.py:43 [high] Untrusted content is framed by a fixed delimiter ('## Source: \n\n```'...'```') that the content itself can close. || return f"## Source: {path.name}\n\n```\n{content}\n```\n"
  owasp_llm_audit/collector.py:67 [high] Untrusted content is framed by a fixed delimiter ('```'...'```') that the content itself can close. || section = f"## File: {rel}\n\n```{filepath.suffix.lstrip('.')}\n{content}\n```\n"
== CUEC_Crosscheck: 2 (0.1s)
  cuec_crosscheck.py:109 [high] Untrusted text is spliced into the prompt sent by client.messages.create() at line 122 without a fence. || "You are an audit assistant performing a completeness check.\n"
  cuec_crosscheck.py:159 [high] Untrusted text is spliced into the prompt sent by client.messages.create() at line 175 without a fence. || "Document 1 (vendor assurance report):\n"
== Track-2-Evidence-Collection-Extraction: 2 (0.1s)
  compliance_qa.py:266 [high] Untrusted content is framed by a fixed delimiter ('<additional_context>'...'</additional_context') that the content itself can close. || f"\n\n<additional_context>\n{additional_context.strip()}\n</additional_context>"
  compliance_qa.py:271 [high] Untrusted content is framed by a fixed delimiter ('<document>'...'</document>') that the content itself can close. || f"<document>\n{document_text}\n</document>"
== OWASP-AI-Testing-Agent: 2 (0.6s)
  owasp_ai_testing_agent/sanitise.py:13 [high] Delimiter neutraliser only matches the bare tag; attribute/whitespace variants such as '</untrusted_input x>' survive and close the trust boundary. || _TAG_RE = re.compile(r"</?\s*untrusted_input\s*>", re.IGNORECASE)
  owasp_ai_testing_agent/sanitise.py:19 [high] Delimiter neutraliser only matches the bare tag; attribute/whitespace variants such as '</untrusted_input x>' survive and close the trust boundary. || "delimiter-attack": re.compile(r"</?\s*untrusted_input\s*>", re.I),
== joiners-movers-leavers-agent: 1 (0.6s)
  ai/claude_runner.py:139 [high] Prompt builder render_user_prompt() splices untrusted text into the prompt without a fence. || out = out.replace(f"[{k}]", str(v))
== Vendor_Guard: 7 (0.2s)
  agents/ai_trust_agent.py:56 [high] Untrusted text is spliced into the prompt sent by complete() at line 52 without a fence. || user=f"Please assess the following AI vendor documents:\n\n{vendor_docs}",
  agents/document_validity_agent.py:224 [high] Untrusted text is spliced into the prompt sent by complete() at line 220 without a fence. || user=f"Extract document validity metadata from the following vendor documents:\n\n{vendor_
  agents/gov_baseline_agent.py:41 [high] Untrusted text is spliced into the prompt sent by complete() at line 37 without a fence. || user=f"Please assess the following vendor documents:\n\n{vendor_docs}",
  agents/orchestrator.py:30 [high] Untrusted text is spliced into the prompt sent by complete() at line 26 without a fence. || user=f"Extract the vendor profile from these documents:\n\n{vendor_docs}",
  agents/resilience_agent.py:41 [high] Untrusted text is spliced into the prompt sent by complete() at line 37 without a fence. || user=f"Please assess the following vendor documents:\n\n{vendor_docs}",
  agents/security_agent.py:53 [high] Untrusted text is spliced into the prompt sent by complete() at line 49 without a fence. || user=f"Please assess the following vendor documents:\n\n{vendor_docs}",
  synthesizer/memo.py:55 [high] Untrusted text is spliced into the prompt sent by complete() at line 62 without a fence. || prompt = MEMO_PROMPT.format(
== judging-found-controls: 1 (0.1s)
  agent.py:122 [high] Untrusted text is spliced into the prompt sent by client.messages.create() at line 125 without a fence. || f"POLICY TEXT:\n{policy_text}\n\n"
== hallucination-detection-agent: 2 (0.1s)
  hallucination/extractor.py:44 [high] Untrusted text is spliced into the prompt sent by call_with_cached_system() at line 48 without a fence. || "Extract all factual claims from the following audit finding:\n\n"
  hallucination/verifier.py:100 [high] Prompt builder _build_user_message() splices untrusted text into the prompt without a fence. || "Verify the following claims extracted from an AI-generated audit finding.\n\n"
== APM-Writer: 0 (0.0s)
== ExecGRC: 0 (0.0s)
== GDPR-AI-Audit-Agent: 0 (0.0s)
== Executive-Summary-Writer: 1 (0.8s)
  scripts/llm_openai.py:81 [high] Untrusted text is spliced into the prompt sent by self.client.chat.completions.create() at line 113 without a fence. || user_content = f"{text}\n\n{task}" if text else task
== Policy-to-Controls-Extractor: 3 (0.2s)
  agent.py:66 [high] Untrusted text is spliced into the prompt sent by client.messages.stream() at line 71 without a fence. || f"Domein: {domain}\n"
  services/docx_extractor copy.py:176 [high] Untrusted text is spliced into the prompt sent by client.messages.create() at line 186 without a fence. || "Hieronder staan genummerde tekstregels uit een beleidsdocument, zonder "
  services/segments.py:102 [high] Untrusted text is spliced into the prompt sent by client.messages.create() at line 113 without a fence. || "Hieronder staan genummerde tekstregels uit een beleidsdocument, zonder "
```
