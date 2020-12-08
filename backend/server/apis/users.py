""" module with all the methods to work with User model """

import logging
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from jose import JWTError

from server.models.users import User
from server.schemas.users import (
    PasswordUpdate,
    AccessToken,
    UserTokens,
    UserBase,
    UserCreate,
)
from server.core import security
from server.core.database import get_session


def get_user(session: Session, user_id: int) -> Optional[User]:
    """it gets user by user's id.

    Args:
        session (Session): connection to database
        user_id (int): id of user

    Returns:
        User: model with given id
    """
    return session.query(User).filter(User.id == user_id).first()


def get_user_by_username(session: Session, username: str) -> Optional[User]:
    """it gets user by username.

    Args:
        session (Session): connection to database
        username (str): username

    Returns:
        User: model with given username
    """
    return session.query(User).filter(User.username == username).first()


def get_user_by_email(session: Session, email: str) -> Optional[User]:
    """it gets user by email.

    Args:
        session (Session): connection to database
        email (str): email of user

    Returns:
        User: model with given email
    """
    return session.query(User).filter(User.email == email).first()


def get_users(session: Session, skip: int = 0, limit: int = 100) -> list[User]:
    """it gets list of users, supports skip and limit parameters.

    Args:
        session (Session): connection to database
        skip (int): parameter to skip first n users. Defaults to 0
        limit (int): parameter to limit read users to n. Defaults to 100

    Returns:
        list[User]: list of users
    """
    return session.query(User).offset(skip).limit(limit).all()


def create_user(session: Session, user: UserCreate) -> User:
    """it creates new user based on provided UserCreate schema.

        it assumes that given user was not created before (responsbility of route).

    Args:
        session (Session): connection to database
        user (UserCreate): schema of user to be created

    Returns:
        User: created model
    """
    db_user = User(
        username=user.username,
        email=user.email,
        hashed_password=security.get_password_hash(user.password),
    )

    session.add(db_user)
    session.commit()
    session.refresh(db_user)

    return db_user


def create_admin_user(session: Session, user: UserCreate) -> User:
    """it creates admin user based on provided schema.

        it assumes that given user was not created before (responsibility of route).

    Args:
        session (Session): connection to database
        user (UserCreate): schema of admin user to be created

    Returns:
        User: created model
    """
    user = create_user(session, user)
    user.is_admin = True

    session.commit()
    session.refresh(user)

    return user


def update_user(
    session: Session,
    current_user: User,
    updated_user: UserBase,
) -> User:
    """it updates current user based on provided schema (email, username).

    Args:
        session (Session): connection to database
        current_user (User): user which will be updated
        user (UserBase): schema with updated values (email, username)

    Returns:
        User: updated model
    """

    current_user.username = updated_user.username
    current_user.email = updated_user.email

    session.commit()
    session.refresh(current_user)

    return current_user


def update_password(
    session: Session,
    current_user: User,
    new_password: PasswordUpdate,
) -> User:
    """it updates user's password.

        it fails if given password is already set.

        Note, that it uses dedicated schema: PasswordUpdate

    Args:
        session (Session): connection to database
        current_user (User): provided model
        new_password (PasswordUpdate): schema with new value for password

    Raises:
        HTTPException: if given password is set

    Returns:
        User: model with updated password
    """
    password = new_password.password

    if security.verify_password(password, current_user.hashed_password):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Password already used")

    current_user.hashed_password = security.get_password_hash(password)

    session.commit()
    session.refresh(current_user)

    return current_user


def delete_user(session: Session, current_user: User):
    """it deletes given user.

    Args:
        session (Session): connection to database
        current_user (User): provided model
    """
    session.delete(current_user)
    session.commit()


def authenticate_user(session: Session, username: str, password: str) -> User:
    """it authenticates user based on given username and password

    Args:
        session (Session): connection to database
        username (str): username
        password (str): password of user

    Returns:
        User: model with given username
    """
    user = get_user_by_username(session, username)

    if not user:
        return False

    if not security.verify_password(password, user.hashed_password):
        return False

    return user


def get_current_user(
    session: Session = Depends(get_session),
    access_token: str = Depends(security.oauth2_scheme_access_token),
) -> User:
    """it gets user based on provided token.

    Args:
        session (Session): connection to database
        token (str): token with user details

    Raises:
        security.CredentialsException: when user provided wrong credentials

    Returns:
        User: provided model
    """

    try:
        token_data = security.process_access_token(access_token)
    except JWTError:
        raise security.CredentialsException(
            "Could not validate credentials"
        ) from JWTError

    user = get_user_by_username(session, username=token_data.username)

    if not user:
        raise security.CredentialsException("Could not validate credentials")

    return user


def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """it gets active user.

        if user is not active, it raises HTTP exception

    Args:
        current_user (User): model to be checked

    Raises:
        HTTPException: when provided user is not active

    Returns:
        User: provided model
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user"
        )
    return current_user


def get_current_admin_user(
    current_user: User = Depends(get_current_active_user),
) -> User:
    """it gets active user with admin priviliges.

        if provided user is not admin, it raises HTTP exception

    Args:
        current_user (User): provided model

    Raises:
        HTTPException: when given user does not have admin priviliges

    Returns:
        User: provided model
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="User is not admin"
        )
    return current_user


def get_access_token_from_refresh_token(
    refresh_token: str, session: Session = Depends(get_session)
) -> AccessToken:
    """it gets access token from given access token

    Args:
        refresh_token (str): value of refresh token
        session (Session): connection to database

    Raises:
        security.CredentialsException: when token is not valid

    Returns:
        AccessToken: desired token
    """
    try:
        token_data = security.process_refresh_token(refresh_token)
        user = get_user_by_username(session, token_data.username)
    except JWTError:
        raise security.CredentialsException(
            "Could not validate credentials"
        ) from JWTError

    user = get_user_by_username(session, username=token_data.username)

    if not user:
        raise security.CredentialsException("Could not validate credentials")

    return security.get_access_token(user)


def get_tokens(
    session: Session, form_data: OAuth2PasswordRequestForm = Depends()
) -> UserTokens:
    """it gets tokens based on given form data with username and password.

        it will try to sign in user based on provided credentials.

        it calls authenticate_user function.

        it raises CredentialsExpection when given credentials are incorrect.

    Args:
        session (Session): connection to database
        form_data (OAuth2PasswordRequestForm): form data with credentials (username, password)

    Raises:
        security.CredentialsException: when provided form data is incorrect

    Returns:
        Token: token with authorized user
    """
    user = authenticate_user(session, form_data.username, form_data.password)

    if not user:
        raise security.CredentialsException("Incorrect username or password")

    return UserTokens(
        access_token=security.get_access_token(user),
        refresh_token=security.get_refresh_token(user),
    )
