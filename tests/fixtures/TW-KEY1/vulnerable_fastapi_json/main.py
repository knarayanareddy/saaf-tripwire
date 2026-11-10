import os
from fastapi import FastAPI
from fastapi.responses import JSONResponse

app = FastAPI()
TOKEN_NAME = "GITHUB_TOKEN"


@app.get("/config")
def config():
    return JSONResponse({"token": os.environ.get("GITHUB_TOKEN")})


@app.get("/page", response_class=None)
def page(request):
    secret = os.getenv("BACKEND_API_KEY")
    return templates.TemplateResponse("page.html", {"request": request, "secret": secret})
