def render(items):
    return ''.join('<li>%s</li>' % item['title'] for item in items)
