from flask import Flask
app = Flask(__name__)
@app.after_request
def c(resp):
    resp.headers.add('Access-Control-Allow-Origin', '*')
    return resp
