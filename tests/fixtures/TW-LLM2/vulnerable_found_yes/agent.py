import json
import anthropic


def judge_control(client: anthropic.Anthropic, policy_text: str, control: dict) -> dict:
    message = client.messages.create(model="m", max_tokens=100, system="Return found, page_no, paragraph",
                                     messages=[{"role": "user", "content": "x"}])
    raw = message.content[0].text.strip()
    verdict = json.loads(raw)
    missing = {"found", "page_no", "paragraph"} - verdict.keys()
    if missing:
        raise ValueError(missing)
    return verdict
