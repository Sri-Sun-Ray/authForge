"""Authentication endpoints.

Milestone 4 adds: POST /verify-email, /password-reset, /password-reset/confirm
                  GET /google, /google/callback (Authlib)
"""

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, unauthorized
from app.db.session import get_db
from app.models import User
from app.schemas.auth import RefreshRequest, RegisterRequest, TokenPair, UserOut
from app.services import auth_service
from app.services.auth_service import ClientInfo

router = APIRouter(prefix="/auth", tags=["auth"])


def client_info(request: Request) -> ClientInfo:
    return ClientInfo(
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def register(body: RegisterRequest, db: AsyncSession = Depends(get_db)) -> User:
    try:
        return await auth_service.register_user(db, body.email, body.password)
    except auth_service.EmailAlreadyRegistered as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, "Email is already registered") from exc


@router.post("/login", response_model=TokenPair)
async def login(
    request: Request,
    form: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
) -> TokenPair:
    """OAuth2 password flow: send `username` (your email) and `password` as form data."""
    try:
        return await auth_service.login(db, form.username, form.password, client_info(request))
    except auth_service.InvalidCredentials as exc:
        # Same message for unknown email and wrong password
        raise unauthorized("Incorrect email or password") from exc


@router.post("/refresh", response_model=TokenPair)
async def refresh(
    body: RefreshRequest, request: Request, db: AsyncSession = Depends(get_db)
) -> TokenPair:
    try:
        return await auth_service.rotate_refresh_token(db, body.refresh_token, client_info(request))
    except auth_service.InvalidRefreshToken as exc:
        raise unauthorized("Invalid or expired refresh token") from exc


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(body: RefreshRequest, db: AsyncSession = Depends(get_db)) -> Response:
    await auth_service.logout(db, body.refresh_token)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/me", response_model=UserOut)
async def me(user: User = Depends(get_current_user)) -> User:
    return user
