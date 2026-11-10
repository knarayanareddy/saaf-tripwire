import os
from fastapi import FastAPI

app = FastAPI()


@app.get("/status")
def status():
    configured = bool(os.getenv("ANTHROPIC_API_KEY"))
    return {"key_configured": configured, "model": os.getenv("MODEL_NAME", "claude")}
