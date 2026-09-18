"""Authentication endpoints.

Milestone 1: POST /register, /login, /refresh, /logout
  - refresh rotates the token; reuse of a revoked token revokes its whole family
Milestone 4: POST /verify-email, /password-reset, /password-reset/confirm
             GET /google, /google/callback (Authlib)
"""

from fastapi import APIRouter

router = APIRouter(prefix="/auth", tags=["auth"])
