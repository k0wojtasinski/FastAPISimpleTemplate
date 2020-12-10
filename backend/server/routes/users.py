""" module with all the User endpoints """

from fastapi import APIRouter, Depends, HTTPException, Response, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from server.apis import users as users_api
from server.core import security
from server.core.database import get_session
from server.core.settings import settings
from server.models.users import User
from server.schemas.users import (
    PasswordUpdate,
    AccessToken,
    RefreshToken,
    UserSchema,
    UserCreate,
)

router = APIRouter()


def convert_user_to_schema(user: User) -> UserSchema:
    """it converts user model into schema of user.

    Args:
        user (User): model to be converted

    Returns:
        UserSchema: converted schema
    """
    return UserSchema(
        id=user.id,
        username=user.username,
        email=user.email,
        is_active=user.is_active,
        is_admin=user.is_admin,
    )


@router.post("/users/")
def post_user(user: UserCreate, session: Session = Depends(get_session)) -> UserSchema:
    """this is route to create new user.

    Args:
        user (UserCreate): schema of user to be created
        session (Session): connection to database

    Raises:
        HTTPException: when user with given username or password already exists

    Returns:
        UserSchema: schema of user
    """
    users_api.check_if_user_exists(session, user)
    user = users_api.create_user(session=session, user=user)

    return convert_user_to_schema(user)


@router.get("/users")
def get_users(
    skip: int = 0,
    limit: int = 100,
    session: Session = Depends(get_session),
    current_user: User = Depends(users_api.get_current_active_user),
) -> list[UserSchema]:
    """it is route to read list of users.


    Args:
        skip (int): parameter to skip first n users. Defaults to 0
        limit (int): parameter to limit read users to n. Defaults to 100
        session (Session): connection to database
        current_user (User): model of current user, must be authorized!

    Returns:
        list[UserSchema]: list of users' schemas
    """
    users = [
        convert_user_to_schema(user)
        for user in users_api.get_users(session=session, skip=skip, limit=limit)
    ]
    return users


@router.get("/users/me")
def get_users_me(
    session=Depends(get_session),
    current_user: User = Depends(users_api.get_current_active_user),
) -> UserSchema:
    """it is route to get current user - user who authorizes call

    Args:
        session (Session): connection to database
        current_user (User): model of current user, must be authorized!

    Returns:
        UserSchema: schema of current user
    """
    return convert_user_to_schema(current_user)


@router.get("/users/{user_id}")
def get_user(
    user_id: int,
    session: Session = Depends(get_session),
    current_user: User = Depends(users_api.get_current_active_user),
) -> UserSchema:
    """it is route to get user based on given id.

        it raises HTTPException when user does not exist.

    Args:
        user_id (int): id of user
        session (Session): connection to database
        current_user (User): model of current user, must be authorized!

    Raises:
        HTTPException: when user with given id does not exist

    Returns:
        UserSchema: schema of user
    """
    db_user = users_api.get_user(session=session, user_id=user_id)

    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    return convert_user_to_schema(db_user)


@router.post("/users/token/")
def post_tokens(
    response: Response,
    session: Session = Depends(get_session),
    form_data: OAuth2PasswordRequestForm = Depends(),
) -> AccessToken:
    """it is route to get access token and refresh token for user.

        it tries to authenticate user based on form data (username, password).

        it sends refresh token as a cookie with httpOnly set to True
        (not available to client JS scripts)

        it sends access token as a standard JSON payload

    Args:
        session (Session): connection to database
        form_data (OAuth2PasswordRequestForm): form data with credentials (username, password)

    Returns:
        Token: schema with access token for given user
    """
    tokens = users_api.get_tokens(session=session, form_data=form_data)

    access_token = tokens.access_token
    refresh_token = tokens.refresh_token

    response.set_cookie(
        "Authorization",
        refresh_token.refresh_token,
        expires=settings.refresh_token_expire_seconds,
        httponly=True,
    )

    return access_token


@router.put("/users/me")
def update_user(
    updated_user: UserCreate,
    session: Session = Depends(get_session),
    current_user: User = Depends(users_api.get_current_active_user),
) -> UserSchema:
    """it is route to update user (username, email) based on UserCreate schema.


    Args:
        updated_user (UserCreate): schema to update user
        session (Session): connection to database
        current_user (User): model of current user, must be authorized!

    Returns:
        UserSchema: schema of updated user
    """

    return users_api.update_user(
        session=session, current_user=current_user, updated_user=updated_user
    )


@router.patch("/users/password/me")
def update_password(
    password: PasswordUpdate,
    session: Session = Depends(get_session),
    current_user: User = Depends(users_api.get_current_active_user),
) -> Response:
    """it is route to update password for user.

    Args:
        password (PasswordUpdate): schema to update password
        session (Session): connection to database
        current_user (User): model of current user, must be authorized!

    Returns:
        Response: response with 204 code when update is successful
    """
    users_api.update_password(
        session=session, current_user=current_user, new_password=password
    )

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete("/users/me")
def delete_user(
    session: Session = Depends(get_session),
    current_user: User = Depends(users_api.get_current_active_user),
) -> Response:
    """it is route to delete current user.

    Args:
        session (Session): connection to database
        current_user (User): model of current user, must be authorized!

    Returns:
        Response: response with 204 code when update is successful
    """
    users_api.delete_user(session=session, current_user=current_user)

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/users/logout")
def logout_user(
    response: Response,
    session: Session = Depends(get_session),
    current_user: User = Depends(users_api.get_current_active_user),
) -> dict:
    """it is route to logout user, by removing refresh token cookie from client

    access token should be removed by client

    Args:
        response (Response): object used to remove cookie
        session (Session): connection to database
        current_user (User): model of current user, must be authorized!

    Returns:
        dict: empty response
    """
    response.delete_cookie("Authorization")
    return {}


@router.post("/users/token/refresh")
def use_refresh_token(
    request: Request, session: Session = Depends(get_session)
) -> AccessToken:
    """it is route to refresh access token based on refresh token from cookie

    Args:
        response (Response): object used to remove cookie
        session (Session): connection to database

    Raises:
        security.CredentialsException: when refresh token is not present or it is not valid

    Returns:
        AccessToken: desired token
    """
    refresh_token = request.cookies.get("Authorization")
    if refresh_token:
        return users_api.get_access_token_from_refresh_token(
            request.cookies.get("Authorization"), session
        )
    raise security.CredentialsException("Refresh token is not present")
