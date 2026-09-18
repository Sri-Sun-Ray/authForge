"""Milestone 1: GET /.well-known/jwks.json returns security.get_jwks()."""

from fastapi import APIRouter

router = APIRouter(prefix="/.well-known", tags=["well-known"])
