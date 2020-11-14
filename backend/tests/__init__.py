import os
from pathlib import Path
import sys

from dotenv import load_dotenv

# loading .env configuration for unit tests
load_dotenv(Path("tests/test.env"))

# loading server directory for unit tests
sys.path.append(Path("../server"))

from fastapi.testclient import TestClient

from server.schemas.users import UserCreate


def get_auth_credentials(test_client: TestClient, user_schema: UserCreate) -> dict:
    response = test_client.post(
        "/users/token/",
        {"username": user_schema["username"], "password": user_schema["password"]},
    )
    return {"Authorization": f'bearer {response.json()["access_token"]}'}
