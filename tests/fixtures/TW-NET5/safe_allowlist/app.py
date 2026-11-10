import urllib.request
from urllib.parse import urlparse
from flask import Flask, request
app = Flask(__name__)
ALLOWED = {"raw.githubusercontent.com"}

@app.route("/update", methods=["POST"])
def update():
    url = request.get_json()["url"]
    if urlparse(url).scheme != "https" or urlparse(url).hostname not in ALLOWED:
        return {"error": "not allowed"}, 400
    return urllib.request.urlopen(url).read()
