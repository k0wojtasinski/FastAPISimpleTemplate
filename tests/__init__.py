import sys
import os

from fastapi.testclient import TestClient

from server.core.schemas import UserCreate

sys.path.append(os.path.abspath("../server"))


def get_auth_credentials(test_client: TestClient, user_schema: UserCreate) -> dict:
    response = test_client.post(
        "/users/token/",
        {"username": user_schema["username"], "password": user_schema["password"]},
    )
    return {"Authorization": f'bearer {response.json()["access_token"]}'}
