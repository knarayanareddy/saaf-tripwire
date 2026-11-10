import uvicorn
from fastapi import FastAPI, Depends
from fastapi.security import HTTPBearer
bearer = HTTPBearer()
app = FastAPI(dependencies=[Depends(bearer)])

@app.get("/data")
def data():
    return {}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
