""" module with unit tests for users endpoints
    Please note that test environment has admin user as a first user (see conftest.py) """

from fastapi import status

from tests.conftest import get_auth_credentials


def test_user_can_sign_up(test_client, user_json):
    sign_up_user = test_client.post("/users/", json=user_json)
    sign_up_user_response = sign_up_user.json()

    assert sign_up_user.status_code == status.HTTP_200_OK
    assert sign_up_user_response["username"] == user_json["username"]
    assert sign_up_user_response["email"] == user_json["email"]

    headers = get_auth_credentials(test_client, user_json)

    list_users = test_client.get("/users", headers=headers)

    assert list_users.status_code == status.HTTP_200_OK
    assert list_users.json()[1] == sign_up_user_response


def test_user_cannot_sign_up_with_already_used_username(test_client, user_json):
    test_client.post("/users/", json=user_json)
    second_sign_up_user = test_client.post("/users/", json=user_json)

    assert second_sign_up_user.status_code == status.HTTP_400_BAD_REQUEST
    assert second_sign_up_user.json()["detail"] == "Username already registered"


def test_user_cannot_sign_up_with_already_used_email(test_client, user_json):
    modified_user = user_json.copy()
    modified_user["username"] = "abc"

    test_client.post("/users/", json=user_json)
    second_sign_up_user = test_client.post("/users/", json=modified_user)

    assert second_sign_up_user.status_code == status.HTTP_400_BAD_REQUEST
    assert second_sign_up_user.json()["detail"] == "Email already registered"


def test_user_can_sign_in(test_client, user_json):
    test_client.post("/users/", json=user_json)

    sign_in_request = test_client.post(
        "/users/token/",
        {"username": user_json["username"], "password": user_json["password"]},
    )
    headers = {"Authorization": f'bearer {sign_in_request.json()["access_token"]}'}

    check_current_user = test_client.get("/users/me", headers=headers)
    check_current_user_response = check_current_user.json()

    assert "Authorization=" in sign_in_request.headers.get("set-cookie")
    assert check_current_user.status_code == status.HTTP_200_OK
    assert check_current_user_response["username"] == user_json["username"]
    assert check_current_user_response["email"] == user_json["email"]


def test_user_can_change_its_fields(test_client, user_json):
    test_client.post("/users/", json=user_json)

    headers = get_auth_credentials(test_client, user_json)

    modified_user = user_json.copy()
    modified_user["username"] = user_json["username"][::-1]
    modified_user["email"] = f'new{user_json["email"]}'

    change_username = test_client.put("/users/me", json=modified_user, headers=headers)

    assert change_username.status_code == status.HTTP_200_OK
    assert change_username.json()["username"] == modified_user["username"]
    assert change_username.json()["email"] == modified_user["email"]

    headers = get_auth_credentials(test_client, modified_user)

    current_user = test_client.get("/users/me", headers=headers)

    assert current_user.status_code == status.HTTP_200_OK
    assert current_user.json()["username"] == modified_user["username"]
    assert current_user.json()["email"] == modified_user["email"]
    assert current_user.json()["id"] == 2


def test_user_can_change_its_password(test_client, user_json):
    test_client.post("/users/", json=user_json)

    headers = get_auth_credentials(test_client, user_json)

    change_password = test_client.patch(
        "/users/password/me", headers=headers, json={"password": "new_password"}
    )

    assert change_password.status_code == status.HTTP_204_NO_CONTENT

    sign_in_with_new_password = test_client.post(
        "/users/token/", {"username": user_json["username"], "password": "new_password"}
    )

    assert sign_in_with_new_password.status_code == status.HTTP_200_OK

    sign_in_with_new_password = test_client.post(
        "/users/token/",
        {"username": user_json["username"], "password": user_json["password"]},
    )

    assert sign_in_with_new_password.status_code == status.HTTP_401_UNAUTHORIZED


def test_unauthorized_user_cannot_access_protected_paths(test_client):
    list_user_without_authorization = test_client.get("/users")
    get_user_without_authorization = test_client.get("/users/1")

    assert list_user_without_authorization.status_code == status.HTTP_401_UNAUTHORIZED
    assert get_user_without_authorization.status_code == status.HTTP_401_UNAUTHORIZED


def test_user_can_delete_itself(test_client, user_json):
    test_client.post("/users/", json=user_json)

    second_user = user_json.copy()
    second_user["username"] = second_user["username"][::-1]
    second_user["email"] = f'new{second_user["email"]}'

    test_client.post("/users/", json=second_user)

    headers = get_auth_credentials(test_client, user_json)

    assert len(test_client.get("/users", headers=headers).json()) == 3

    delete_first_user = test_client.delete("/users/me", headers=headers)

    assert delete_first_user.status_code == status.HTTP_204_NO_CONTENT

    headers = get_auth_credentials(test_client, second_user)

    assert len(test_client.get("/users", headers=headers).json()) == 2
    assert test_client.get("/users", headers=headers).json()[1]["id"] == 3


def test_user_can_signout(test_client, user_json):
    test_client.post("/users/", json=user_json)

    headers = get_auth_credentials(test_client, user_json)

    sign_out_user = test_client.post("/users/logout", headers=headers)

    assert 'Authorization=""' in sign_out_user.headers["set-cookie"]
    assert not sign_out_user.cookies


def test_user_can_use_refresh_token(test_client, user_json):
    test_client.post("/users/", json=user_json)

    sign_in_request = test_client.post(
        "/users/token/",
        {"username": user_json["username"], "password": user_json["password"]},
    )

    refresh_token = sign_in_request.headers["set-cookie"].split("=", 1)

    refresh_token_request = test_client.post(
        "/users/token/refresh", headers={refresh_token[0]: refresh_token[1]}
    )
    access_token = refresh_token_request.json()

    check_current_user_request = test_client.get(
        "/users/me",
        headers={
            "Authorization": f"{access_token.get('token_type')} {access_token.get('access_token')}"
        },
    )

    assert check_current_user_request.status_code == status.HTTP_200_OK
