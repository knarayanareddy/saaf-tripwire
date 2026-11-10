from flask import Flask, request, abort
app = Flask(__name__)
@app.before_request
def gate():
    a = request.authorization
    if not a or a.password != 's':
        abort(401)
app.run(host='0.0.0.0')
