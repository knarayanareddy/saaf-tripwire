import os, uvicorn
HOST = os.getenv("HOST", "0.0.0.0")
if __name__ == "__main__":
    uvicorn.run("app.main:app", host=HOST, port=8000)
