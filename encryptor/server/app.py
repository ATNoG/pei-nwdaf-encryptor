from contextlib import asynccontextmanager
from fastapi import FastAPI
from crypto.encryptor import Encryptor
from encryptor.server.router import router as handshake_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.encryptor = Encryptor()
    app.state.shared_key = None
    yield


def create_app() -> FastAPI:
    app = FastAPI(title="NWDAF Encryptor", lifespan=lifespan)
    app.include_router(handshake_router, prefix="/crypto")
    return app


app = create_app()
