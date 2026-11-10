import uvicorn
from fastapi import FastAPI
app = FastAPI()
@app.get('/run')
def run(): return {}
if __name__ == '__main__':
    host = '0.0.0.0'
    uvicorn.run(app, host=host, port=8000)
