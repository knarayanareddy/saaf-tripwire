def render(rows):
    return ''.join('<td>{}</td>'.format(row['name']) for row in rows)
