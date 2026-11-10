import json

def render(rows):
    body = []
    for r in rows:
        control = r.get("control_description") or "<span>none</span>"
        body.append(f"<tr><td>{control}</td><td>{r['owner']}</td></tr>")
    return "<table>" + "".join(body) + "</table>"
