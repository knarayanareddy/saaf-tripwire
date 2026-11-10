import uvicorn
from pydantic_settings import BaseSettings
class Settings(BaseSettings):
    host: str = '0.0.0.0'
s = Settings()
from fastapi import FastAPI
app = FastAPI()
uvicorn.run(app, host=s.host)
