import anthropic
from tripwire.fence import fence, SYSTEM_RULE

def ask(document_text, question):
    client = anthropic.Anthropic()
    user = f"{fence(document_text, source='policy.pdf')}\n\nQuestion: {question}"
    return client.messages.create(model="claude-x", max_tokens=100, system="Be strict.\n" + SYSTEM_RULE,
                                  messages=[{"role": "user", "content": user}])

def ask2(pdf_text):
    client = anthropic.Anthropic()
    pdf_text = fence(pdf_text, "upload.pdf")
    return client.messages.create(model="claude-x", max_tokens=10, messages=[{"role": "user", "content": "Read:\n" + pdf_text}])
