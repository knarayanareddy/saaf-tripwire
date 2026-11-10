import anthropic
from fastapi import FastAPI
app = FastAPI()
client = anthropic.Anthropic()

def summarise(text):
    return client.messages.create(model="claude-x", max_tokens=4000, messages=[{"role": "user", "content": text}])

@app.post("/api/generate-report")
async def generate(body: dict):
    return {"report": summarise(body["text"])}
