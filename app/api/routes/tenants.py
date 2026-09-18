"""Tenant endpoints.

Milestone 2: POST /tenants, GET /tenants (mine), POST /tenants/{id}/switch,
             POST /tenants/{id}/invites, POST /invites/{token}/accept
"""

from fastapi import APIRouter

router = APIRouter(prefix="/tenants", tags=["tenants"])
