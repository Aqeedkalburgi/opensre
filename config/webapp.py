from __future__ import annotations

import os
import secrets
from fastapi import FastAPI, Response, Request, Header, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ValidationError

from config.config import LLMSettings, get_environment
from config.version import get_version
from platform.observability.sentry_sdk import init_sentry
from integrations.telegram.inbound import parse_telegram_update
from integrations.telegram.handler import handle_telegram_message

init_sentry(entrypoint="webapp")


class HealthResponse(BaseModel):
    ok: bool
    version: str
    llm_configured: bool
    env: str


app = FastAPI()


def _llm_configured() -> bool:
    try:
        LLMSettings.from_env()
    except ValidationError:
        return False
    return True


def get_health_response() -> HealthResponse:
    llm_configured = _llm_configured()

    return HealthResponse(
        ok=llm_configured,
        version=get_version(),
        llm_configured=llm_configured,
        env=get_environment().value,
    )


@app.get("/", response_model=HealthResponse)
@app.get("/health", response_model=HealthResponse)
@app.get("/ok", response_model=HealthResponse)
def health(response: Response) -> HealthResponse:
    health_response = get_health_response()
    response.status_code = (
        status.HTTP_200_OK if health_response.ok else status.HTTP_503_SERVICE_UNAVAILABLE
    )
    return health_response


@app.post("/telegram/webhook")
async def telegram_webhook(
    request: Request,
    x_telegram_bot_api_secret_token: str | None = Header(default=None),
) -> JSONResponse:
    secret = os.environ.get("TELEGRAM_WEBHOOK_SECRET", "").strip()
    if secret:
        if not x_telegram_bot_api_secret_token or not secrets.compare_digest(
            x_telegram_bot_api_secret_token, secret
        ):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid payload")

    if not isinstance(body, dict):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid payload")

    normalized = parse_telegram_update(body)
    if normalized is not None:
        await handle_telegram_message(normalized)

    return JSONResponse({"ok": True})
