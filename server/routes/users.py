""" module with all the User endpoints """

from sqlalchemy.orm import Session
from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.security import OAuth2PasswordRequestForm

from server.core import models, schemas, security
from server.core.database import get_session
from server.apis import users as users_api

router = APIRouter()


def convert_user_to_schema(user: models.User) -> schemas.User:
    return schemas.User(
        id=user.id,
        username=user.username,
        email=user.email,
        is_active=user.is_active,
        is_admin=user.is_admin,
    )


@router.post("/users/")
def post_user(
    user: schemas.UserCreate, session: Session = Depends(get_session)
) -> schemas.User:
    db_user = users_api.read_user_by_username(session=session, username=user.username)

    if db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered",
        )

    db_user = users_api.read_user_by_email(session=session, email=user.email)

    if db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered"
        )

    user = users_api.create_user(session=session, user=user)

    return convert_user_to_schema(user)


@router.get("/users")
def get_users(
    skip: int = 0,
    limit: int = 100,
    session: Session = Depends(get_session),
    current_user: models.User = Depends(users_api.get_current_active_user),
) -> list[schemas.User]:
    users = [
        convert_user_to_schema(user)
        for user in users_api.read_users(session=session, skip=skip, limit=limit)
    ]
    return users


@router.get("/users/me")
def read_users_me(
    session=Depends(get_session),
    current_user: models.User = Depends(users_api.get_current_active_user),
) -> schemas.User:
    return convert_user_to_schema(current_user)


@router.get("/users/{user_id}")
def read_user(
    user_id: int,
    session: Session = Depends(get_session),
    current_user: models.User = Depends(users_api.get_current_active_user),
) -> schemas.User:
    db_user = users_api.read_user(session=session, user_id=user_id)

    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    return db_user


@router.post("/users/token/")
def post_token(
    session: Session = Depends(get_session),
    form_data: OAuth2PasswordRequestForm = Depends(),
) -> schemas.Token:
    return users_api.get_token(session, form_data)


@router.put("/users/me")
def update_user(
    user: schemas.UserCreate,
    session: Session = Depends(get_session),
    current_user: models.User = Depends(users_api.get_current_active_user),
) -> schemas.User:

    return users_api.update_user(user, session, current_user)


@router.patch("/users/password")
def update_password(
    password: schemas.PasswordUpdate,
    session: Session = Depends(get_session),
    current_user: models.User = Depends(users_api.get_current_active_user),
):
    users_api.update_password(password, session, current_user)

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete("/users/me")
def delete_user(
    session: Session = Depends(get_session),
    current_user: models.User = Depends(users_api.get_current_active_user),
):
    users_api.delete_user(session, current_user)

    return Response(status_code=status.HTTP_204_NO_CONTENT)
