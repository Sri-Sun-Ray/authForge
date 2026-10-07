"""Outgoing email.

There is no SMTP provider wired up: messages are logged, and kept in a small in-memory
outbox outside production so local runs and tests can read them. Swapping in SES,
SendGrid or Postmark means replacing `send_email` and nothing else.
"""

import logging
from collections import deque
from dataclasses import dataclass

from app.core.config import get_settings

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Email:
    to: str
    subject: str
    body: str


# Bounded so a long-running local server cannot grow it without limit
outbox: deque[Email] = deque(maxlen=100)


async def send_email(to: str, subject: str, body: str) -> None:
    settings = get_settings()
    logger.info("Email to %s: %s", to, subject)
    if settings.environment != "production":
        outbox.append(Email(to=to, subject=subject, body=body))


def link(path: str, token: str) -> str:
    return f"{get_settings().app_base_url.rstrip('/')}{path}?token={token}"
