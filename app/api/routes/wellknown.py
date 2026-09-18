from typing import Any

from fastapi import APIRouter, Response

from app.core.security import get_jwks

router = APIRouter(prefix="/.well-known", tags=["well-known"])


@router.get("/jwks.json")
async def jwks(response: Response) -> dict[str, Any]:
    # Clients may cache the keys; keep this short so key rotation propagates quickly
    response.headers["Cache-Control"] = "public, max-age=300"
    return get_jwks()
