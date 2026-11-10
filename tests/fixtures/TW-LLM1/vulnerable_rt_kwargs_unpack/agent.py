import anthropic
c = anthropic.Anthropic()
def review(document):
    params = dict(model='m', max_tokens=10, messages=[{'role':'user','content': f'Review: {document}'}])
    return c.messages.create(**params)
