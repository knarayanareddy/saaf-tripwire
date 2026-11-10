import anthropic
c = anthropic.Anthropic()
def ask(text):
    return c.messages.create(model='m', max_tokens=10, messages=[{'role':'user','content': text}])
def review(document):
    return ask(f'Review this: {document}')
