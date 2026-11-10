import json
from openai import OpenAI
from models import VendorProfile


def build_profile(client: OpenAI):
    r = client.chat.completions.create(model="gpt", messages=[{"role": "user", "content": "extract"}])
    data = json.loads(r.choices[0].message.content)
    return VendorProfile(**data)


def escalate(client: OpenAI, finding):
    r = client.chat.completions.create(model="gpt", messages=[{"role": "user", "content": "enrich"}])
    enriched = json.loads(r.choices[0].message.content)
    priority = enriched.get("priority") or 3
    return priority
