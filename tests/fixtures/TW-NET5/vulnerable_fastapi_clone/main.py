import subprocess, tempfile, requests
from fastapi import FastAPI
from pydantic import BaseModel
app = FastAPI()

class Req(BaseModel):
    repo: str

@app.post("/fetch-repo")
def fetch_repo(req: Req):
    tmp = tempfile.mkdtemp()
    subprocess.run(["git", "clone", "--depth", "1", req.repo, tmp], check=True)
    return {"ok": True}

@app.get("/proxy")
def proxy(target: str):
    return requests.get(target, timeout=5).text
