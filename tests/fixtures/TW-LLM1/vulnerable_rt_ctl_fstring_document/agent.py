import anthropic
c = anthropic.Anthropic()
def review(document):
    return c.messages.create(model='m', max_tokens=10, messages=[{'role':'user','content': f'Review: {document}'}])
