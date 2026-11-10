import os
from flask import Flask, render_template

app = Flask(__name__)


@app.route('/')
def index():
    return render_template('index.html',
                           default_api_key=os.getenv('ANTHROPIC_API_KEY', ''))


@app.route("/settings")
def settings():
    key = os.environ["OPENAI_API_KEY"]
    return {"model": "gpt", "api_key": key}
