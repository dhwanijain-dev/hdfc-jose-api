from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from app.config import Settings
from app.jose_service import JoseConfigurationError, JosePayloadError, JoseService


class EncryptRequest(BaseModel):
    model_config = ConfigDict(extra="allow")


class EncryptResponse(BaseModel):
    jose: str
    content_type: str = "application/jose"


class DecryptRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    jose: str = Field(min_length=1)


class DecryptResponse(BaseModel):
    payload: dict[str, Any]


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = Settings.from_environment()
    try:
        app.state.jose_service = JoseService(settings)
    except JoseConfigurationError as exc:
        raise RuntimeError(f"JOSE configuration failed: {exc}") from exc
    app.state.settings = settings
    yield


app = FastAPI(
    title="CorpPay JOSE Utility API",
    description="Signs and encrypts CorpPay JSON requests and decrypts and verifies responses.",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/encrypt", response_model=EncryptResponse)
async def encrypt_payload(body: EncryptRequest, request: Request) -> EncryptResponse:
    payload = body.model_dump(exclude_unset=True)
    if not payload:
        raise HTTPException(status_code=422, detail="Request body must contain the bank API payload")
    try:
        compact_jose = request.app.state.jose_service.encrypt_request(payload)
    except JosePayloadError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return EncryptResponse(jose=compact_jose)


@app.post("/decrypt", response_model=DecryptResponse)
async def decrypt_payload(body: DecryptRequest, request: Request) -> DecryptResponse:
    try:
        payload = request.app.state.jose_service.decrypt_response(body.jose)
    except JosePayloadError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return DecryptResponse(payload=payload)


@app.middleware("http")
async def request_size_limit(request: Request, call_next):
    settings = getattr(request.app.state, "settings", None)
    if settings and request.headers.get("content-length"):
        try:
            content_length = int(request.headers["content-length"])
        except ValueError:
            return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length"})
        if content_length > settings.max_request_bytes:
            return JSONResponse(status_code=413, content={"detail": "Request body too large"})
    response = await call_next(request)
    return response
