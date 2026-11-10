import os
from flask import Flask
app = Flask(__name__)

@app.route('/api/reset', methods=['POST'])
def reset():
    for f in os.listdir("data"):
        os.remove(os.path.join("data", f))
    return {"ok": True}
