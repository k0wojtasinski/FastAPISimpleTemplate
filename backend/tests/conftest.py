""" module with pytest configuration and fixtures """

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from server import app
from server.models import Base
from server.core.database import get_session
from server.core.utils import generate_user_create_dict, create_admin

from server.schemas.users import UserCreate


def get_auth_credentials(client: TestClient, user_schema: UserCreate) -> dict:
    response = client.post(
        "/users/token/",
        {"username": user_schema["username"], "password": user_schema["password"]},
    )
    return {"Authorization": f'bearer {response.json()["access_token"]}'}


@pytest.fixture
def test_session():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )

    testing_session_local = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    Base.metadata.create_all(bind=engine)

    session = testing_session_local()

    try:
        session = testing_session_local()
        yield session
    finally:
        session.close()


@pytest.fixture
def test_client() -> TestClient:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )

    testing_session_local = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    Base.metadata.create_all(bind=engine)

    def _override_get_session():
        try:
            session = testing_session_local()
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_session] = _override_get_session

    # create first admin user
    create_admin(
        username="admin",
        password="password",
        email="admin_user@example.com",
        session=testing_session_local(),
    )

    return TestClient(app)


@pytest.fixture
def user_json() -> dict:
    return generate_user_create_dict()
