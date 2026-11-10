def render(rows):
    out = ''
    for row in rows:
        out += f'<td>{row["name"]}</td>'
    return out
