""" module with all the methods to work with User model """

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from jose import JWTError

from server.core import models, schemas, security
from server.core.database import get_session


def read_user(session: Session, user_id: int) -> models.User:
    return session.query(models.User).filter(models.User.id == user_id).first()


def read_user_by_username(session: Session, username: str) -> models.User:
    return session.query(models.User).filter(models.User.username == username).first()


def read_user_by_email(session: Session, email: str) -> models.User:
    return session.query(models.User).filter(models.User.email == email).first()


def read_users(session: Session, skip: int = 0, limit: int = 100) -> list[models.User]:
    return session.query(models.User).offset(skip).limit(limit).all()


def create_user(session: Session, user: schemas.UserCreate) -> models.User:
    db_user = models.User(
        username=user.username,
        email=user.email,
        hashed_password=security.get_password_hash(user.password),
    )

    session.add(db_user)
    session.commit()
    session.refresh(db_user)

    return db_user


def create_admin_user(session: Session, user: schemas.UserCreate) -> models.User:
    user = create_user(session, user)
    user.is_admin = True

    session.commit()
    session.refresh(user)

    return user


def update_user(
    user: schemas.UserBase, session: Session, current_user: models.User
) -> models.User:

    current_user.username = user.username
    current_user.email = user.email

    session.commit()
    session.refresh(current_user)

    return current_user


def update_password(
    new_password: schemas.PasswordUpdate, session: Session, current_user: models.User
) -> models.User:
    password = new_password.password

    if security.verify_password(password, current_user.hashed_password):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Password already used")

    current_user.hashed_password = security.get_password_hash(password)

    session.commit()
    session.refresh(current_user)

    return current_user


def delete_user(session: Session, current_user: models.User):
    session.delete(current_user)
    session.commit()


def authenticate_user(session: Session, username: str, password: str) -> models.User:
    user = read_user_by_username(session, username)

    if not user:
        return False

    if not security.verify_password(password, user.hashed_password):
        return False

    return user


def get_current_user(
    session: Session = Depends(get_session),
    token: str = Depends(security.oauth2_scheme),
) -> models.User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        token_data = security.process_token(token)
    except JWTError:
        raise credentials_exception

    user = read_user_by_username(session, username=token_data.username)

    if not user:
        raise credentials_exception

    return user


def get_current_active_user(
    current_user: models.User = Depends(get_current_user),
) -> models.User:
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user"
        )
    return current_user


def get_token(
    session: Session, form_data: OAuth2PasswordRequestForm = Depends()
) -> schemas.Token:
    user = authenticate_user(session, form_data.username, form_data.password)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return security.get_token(user)
