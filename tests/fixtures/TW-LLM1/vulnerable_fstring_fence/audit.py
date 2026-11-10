import anthropic
from pathlib import Path

def collect(folder):
    out = []
    for p in Path(folder).rglob("*.py"):
        content = p.read_text()
        out.append(f"## File: {p.name}\n\n```python\n{content}\n```\n")
    return "\n".join(out)

def audit(folder):
    material = collect(folder)
    client = anthropic.Anthropic()
    return client.messages.create(model="claude-x", max_tokens=100,
        messages=[{"role": "user", "content": f"Audit this agent:\n{material}"}])
