import json
import anthropic
from tripwire.fence import check_quotes


def audit(raw_source: str):
    resp = anthropic.Anthropic().messages.create(model="m", max_tokens=10, messages=[{"role": "user", "content": "x"}])
    result = json.loads(resp.content[0].text)
    for c in result.get("controls", []):
        evidence = c.get("evidence") or []
        bad = check_quotes(evidence, raw_source) if evidence else ["<none>"]
        if bad and c.get("status") == "PASS":
            c["status"] = "WARN"
    return result
