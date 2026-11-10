import uvicorn, asyncio
from fastapi import FastAPI
app = FastAPI()
config = uvicorn.Config(app, host='0.0.0.0', port=8000)
asyncio.run(uvicorn.Server(config).serve())
