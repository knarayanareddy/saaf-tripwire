from fastapi import FastAPI
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
app = FastAPI(middleware=[Middleware(CORSMiddleware, allow_origins=['*'], allow_methods=['*'])])
