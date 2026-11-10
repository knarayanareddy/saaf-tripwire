from flask import Flask, request
from fetcher import update_definitions
app = Flask(__name__)
DEFAULT_URL = "https://example.org/defs.json"

@app.route("/update", methods=["POST"])
def update():
    data = request.get_json(silent=True) or {}
    url = data.get("url") or DEFAULT_URL
    return update_definitions(url)
