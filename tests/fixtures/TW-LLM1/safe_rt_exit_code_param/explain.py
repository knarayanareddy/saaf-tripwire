import anthropic
c = anthropic.Anthropic()
def explain_failure(exit_code: int):
    return c.messages.create(model='m', max_tokens=10, messages=[{'role':'user','content': f'Process exited with {exit_code}. Explain.'}])
