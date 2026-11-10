import html
from html import escape

def _esc(v):
    return html.escape("" if v is None else str(v))

def render(rows, total):
    body = []
    for r in rows:
        body.append(f"<tr><td>{_esc(r.get('control'))}</td><td>{escape(r['owner'])}</td><td>{r['score']:.1f}</td></tr>")
    prompt = f"<document>{rows}</document>"   # LLM delimiter, not HTML
    return f"<table>{''.join(body)}</table><p>{len(rows)} rows, total {total}</p>"
