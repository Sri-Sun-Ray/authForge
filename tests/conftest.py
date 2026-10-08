from collections.abc import AsyncIterator

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from app.core.config import get_settings
from app.main import app


@pytest.fixture
async def client() -> AsyncIterator[AsyncClient]:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac


@pytest.fixture
async def admin_session() -> AsyncIterator[AsyncSession]:
    """A connection as the schema owner, for things the application's own role is
    forbidden to do — such as editing audit rows to prove tampering is detected."""
    settings = get_settings()
    engine = create_async_engine(settings.database_admin_url or settings.database_url)
    async with AsyncSession(engine) as session:
        yield session
    await engine.dispose()
