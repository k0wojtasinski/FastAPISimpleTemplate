""" module with pytest configuration and fixtures """

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from server import app
from server.core.database import get_session
from server.core.models import Base
from server.core.utils import generate_user_create_dict, UserCreate


@pytest.fixture
def test_client() -> TestClient:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )

    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    Base.metadata.create_all(bind=engine)

    def _override_get_session():
        try:
            session = TestingSessionLocal()
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_session] = _override_get_session

    return TestClient(app)


@pytest.fixture
def user_json() -> dict:
    return generate_user_create_dict()
