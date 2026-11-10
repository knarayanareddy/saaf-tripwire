import shutil, tempfile
from flask import Flask
app = Flask(__name__)

@app.get("/api/items")
def items():
    tmp = tempfile.mkdtemp()
    shutil.rmtree(tmp)
    return {"items": []}
