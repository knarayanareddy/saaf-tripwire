import os
import anthropic
from flask import Flask, render_template, request

app = Flask(__name__)


@app.route('/')
def index():
    return render_template('index.html', default_api_key='')


@app.route('/analyze', methods=['POST'])
def analyze():
    api_key = request.form.get('api_key', '').strip() or os.getenv('ANTHROPIC_API_KEY', '')
    client = anthropic.Anthropic(api_key=api_key)
    return {"ok": True}
