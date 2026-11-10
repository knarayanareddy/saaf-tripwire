from flask import Flask
app = Flask(__name__)
@app.get('/x')
def x(): return 'x'
app.run(host='0.0.0.0')
