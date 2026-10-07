"""Authentication endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import client_ip, get_current_user, rate_limit, unauthorized
from app.core.config import get_settings
from app.core.rate_limit import check_rate_limit
from app.core.redis import get_redis
from app.db.session import get_db
from app.models import User
from app.schemas.auth import (
    OneTimeTokenRequest,
    PasswordResetConfirm,
    PasswordResetRequest,
    RefreshRequest,
    RegisterRequest,
    TokenPair,
    UserOut,
)
from app.services import auth_service
from app.services.auth_service import ClientInfo

router = APIRouter(prefix="/auth", tags=["auth"])


def client_info(request: Request) -> ClientInfo:
    return ClientInfo(ip=client_ip(request), user_agent=request.headers.get("user-agent"))


def too_many_requests(retry_after_seconds: int) -> HTTPException:
    return HTTPException(
        status.HTTP_429_TOO_MANY_REQUESTS,
        "Too many attempts. Try again later.",
        headers={"Retry-After": str(retry_after_seconds)},
    )


@router.post(
    "/register",
    response_model=UserOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit("register", "rate_limit_register_per_hour", 3600))],
)
async def register(body: RegisterRequest, db: AsyncSession = Depends(get_db)) -> User:
    try:
        return await auth_service.register_user(db, body.email, body.password)
    except auth_service.EmailAlreadyRegistered as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, "Email is already registered") from exc


@router.post(
    "/login",
    response_model=TokenPair,
    dependencies=[Depends(rate_limit("login", "rate_limit_login_per_minute", 60))],
)
async def login(
    request: Request,
    form: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
) -> TokenPair:
    """OAuth2 password flow: send `username` (your email) and `password` as form data."""
    settings = get_settings()
    # Limited per account as well as per IP, so a botnet spread over many addresses
    # still cannot grind through passwords for one victim
    account_key = f"rl:login:account:{auth_service.normalize_email(form.username)}"
    per_account = await check_rate_limit(
        redis, account_key, settings.rate_limit_login_per_account_per_minute, 60
    )
    if not per_account.allowed:
        raise too_many_requests(per_account.retry_after_seconds)

    try:
        return await auth_service.login(db, form.username, form.password, client_info(request))
    except auth_service.AccountLocked as exc:
        raise too_many_requests(exc.retry_after_seconds) from exc
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


# --- Email verification and password reset ----------------------------------


@router.post("/verify-email/request", status_code=status.HTTP_202_ACCEPTED)
async def request_email_verification(
    user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)
) -> dict[str, str]:
    await auth_service.request_email_verification(db, user)
    return {"detail": "If the address needs confirming, a link is on its way."}


@router.post("/verify-email/confirm", response_model=UserOut)
async def confirm_email_verification(
    body: OneTimeTokenRequest, db: AsyncSession = Depends(get_db)
) -> User:
    try:
        return await auth_service.confirm_email_verification(db, body.token)
    except auth_service.InvalidOneTimeToken as exc:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "Invalid or expired verification link"
        ) from exc


@router.post(
    "/password-reset",
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[
        Depends(rate_limit("password-reset", "rate_limit_password_reset_per_hour", 3600))
    ],
)
async def request_password_reset(
    body: PasswordResetRequest, db: AsyncSession = Depends(get_db)
) -> dict[str, str]:
    """Always answers the same way, whether or not the address is registered."""
    await auth_service.request_password_reset(db, body.email)
    return {"detail": "If that address has an account, a reset link is on its way."}


@router.post("/password-reset/confirm", status_code=status.HTTP_204_NO_CONTENT)
async def confirm_password_reset(
    body: PasswordResetConfirm, db: AsyncSession = Depends(get_db)
) -> Response:
    try:
        await auth_service.confirm_password_reset(db, body.token, body.new_password)
    except auth_service.InvalidOneTimeToken as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid or expired reset link") from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)
