from fastapi import FastAPI
from .data.db import engine, Base
from .api.v1.endpoints import auth
from .config import settings

# create DB tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Auth Service", version="0.1.0")

app.include_router(auth.router)


@app.get("/")
def root():
    return {"msg": "Auth service running"}
