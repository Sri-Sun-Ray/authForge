"""RBAC endpoints.

Milestone 3: GET/POST /tenants/{id}/roles, PUT /tenants/{id}/roles/{role_id},
             PUT /tenants/{id}/users/{user_id}/roles, GET /permissions
"""

from fastapi import APIRouter

router = APIRouter(tags=["rbac"])
