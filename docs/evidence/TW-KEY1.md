# TW-KEY1 evidence

Run: `engine.run(~/saaf-redteam/work/repos/<repo>, history=False, only={'TW-KEY1'})` (read-only).

## Hits on audited repos

| Repo | Hit | Audit finding |
|---|---|---|
| Finding-analysis | app.py:34 `render_template(..., default_api_key=os.getenv('ANTHROPIC_API_KEY'))` | SA-29 (trace app.py:35 -> templates/index.html:157) |
| Track-2---IAM-final | tools/scripts/access_review_app.py:243 `st.text_input(value=ANTHROPIC_API_KEY)` - type=password, but the value is still sent to the browser | not in audit (new, true positive) |

## Notes, false positives and limits

False-positive review: Executive-Summary-Writer 0 (after excluding `bool(os.getenv(...))` status flags - it was 1), saaf-portal 0,
OWASP-top-10-LLM-assessment 0, Team-HighTable 0.
Known limits: Python only (Flask/FastAPI/Starlette/Streamlit); secrets recognised by env/config key name; Jinja templates that read
`config.SECRET` directly are not inspected.

## Raw run output

```
== Finding-analysis: 1 (0.1s)
  app.py:34 [high] Secret to client: ANTHROPIC_API_KEY is passed to render_template() and ends up in the page/response. || return render_template('index.html',
== Track-2---IAM-final: 1 (0.2s)
  tools/scripts/access_review_app.py:243 [high] Secret to client: ANTHROPIC_API_KEY is passed to st.text_input() and ends up in the page/response. || api_key_input = st.text_input(
== Executive-Summary-Writer: 0 (0.3s)
== saaf-portal: 0 (0.0s)
== OWASP-top-10-LLM-assessment: 0 (0.1s)
== Team-HighTable: 0 (0.1s)
```
