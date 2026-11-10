from flask import Flask, request
app = Flask(__name__)
@app.after_request
def c(resp):
    resp.headers.update({'Access-Control-Allow-Origin': request.headers.get('Origin'), 'Access-Control-Allow-Credentials': 'true'})
    return resp
