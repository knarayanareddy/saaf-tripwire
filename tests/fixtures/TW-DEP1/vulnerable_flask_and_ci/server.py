from flask import Flask
app = Flask(__name__)

@app.route('/x')
def x():
    return 'x'
