from fastapi import FastAPI
app = FastAPI()

@app.post("/api/generate")
def generate(body: dict):
    return {"report": body}
