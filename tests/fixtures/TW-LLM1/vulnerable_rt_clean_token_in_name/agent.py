import anthropic
c = anthropic.Anthropic()
def run(store, i):
    pdf_text_by_id = store.load(i)
    return c.messages.create(model='m', max_tokens=10, messages=[{'role':'user','content': 'Summarise:\n' + pdf_text_by_id}])
