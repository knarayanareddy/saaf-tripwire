from flask import Flask
app = Flask(__name__)
@app.post('/delete')
def d(): return 'ok'
app.run(host='0.0.0.0')
