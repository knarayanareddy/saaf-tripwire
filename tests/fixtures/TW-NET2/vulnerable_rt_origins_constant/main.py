from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
ORIGINS = ['*']
app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=ORIGINS, allow_credentials=True)
