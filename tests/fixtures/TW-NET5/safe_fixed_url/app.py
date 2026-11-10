import requests
from flask import Flask, request
app = Flask(__name__)
UPDATE_URL = "https://example.org/defs.json"

@app.route("/update", methods=["POST"])
def update():
    _ = request.get_json(silent=True)
    return requests.get(UPDATE_URL, timeout=10).text
