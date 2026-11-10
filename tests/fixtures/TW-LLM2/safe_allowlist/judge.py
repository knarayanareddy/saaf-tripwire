import json
import anthropic
ALLOWED = {"yes", "no"}


def judge(policy_text: str) -> dict:
    resp = anthropic.Anthropic().messages.create(model="m", max_tokens=10, messages=[{"role": "user", "content": "x"}])
    verdict = json.loads(resp.content[0].text)
    if verdict.get("found") not in ALLOWED:
        raise ValueError("bad found")
    if verdict["found"] == "yes" and " ".join(verdict["paragraph"].split()) not in " ".join(policy_text.split()):
        raise ValueError("ungrounded")
    return verdict
