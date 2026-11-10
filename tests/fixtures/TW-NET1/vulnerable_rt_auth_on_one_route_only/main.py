import uvicorn
from fastapi import FastAPI, Depends
from fastapi.security import HTTPBearer
app = FastAPI()
bearer = HTTPBearer()
@app.get('/me')
def me(t=Depends(bearer)): return {}
@app.post('/admin/reset')
def reset(): return {}
uvicorn.run(app, host='0.0.0.0')
