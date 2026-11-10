from openai import OpenAI

def ask(document_text: str, question: str):
    client = OpenAI()
    prompt = "<document>\n" + document_text + "\n</document>\nQuestion: " + question
    r = client.chat.completions.create(model='gpt-x', messages=[{'role': 'user', 'content': prompt}])
    return r.choices[0].message.content

def summarise_ticket(ticket):
    client = OpenAI()
    return client.chat.completions.create(model="gpt-x", messages=[{"role": "user", "content": ticket["description"]}])
