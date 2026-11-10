import anthropic

SYSTEM = "You are a helpful assistant."

def greet(name: str, language: str):
    client = anthropic.Anthropic()
    prompt = f"Say hello to {name} in {language}."
    return client.messages.create(model="claude-x", max_tokens=50, system=SYSTEM,
                                  messages=[{"role": "user", "content": prompt}])

def report_html(document_text):
    return f"<div class='doc'>{document_text}</div>"   # HTML rendering, not a prompt
