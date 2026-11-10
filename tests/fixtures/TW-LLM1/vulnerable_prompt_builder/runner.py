import json, subprocess

def render_user_prompt(template, payload):
    values = {"payload_json": json.dumps(payload)}
    out = template
    for k, v in values.items():
        out = out.replace(f"[{k}]", str(v))
    return out

def call_claude(user):
    return subprocess.run(["claude", "-p", "--output-format", "json"], input=user, capture_output=True, text=True)
