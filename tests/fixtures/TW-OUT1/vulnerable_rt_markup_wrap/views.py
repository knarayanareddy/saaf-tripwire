from markupsafe import Markup
def note(n):
    return Markup(n['text'])
