"""Audit log endpoints.

Milestone 5: GET /audit-logs (tenant-scoped; filter by actor, action, target, date),
             GET /audit-logs/verify (walk the hash chain and report tampering)
"""

from fastapi import APIRouter

router = APIRouter(prefix="/audit-logs", tags=["audit"])
