""" module with security configuration and helper functions """

from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
from jose import jwt
from passlib.context import CryptContext

from server.core.settings import settings
from server.core import schemas


SECRET_KEY = settings.secret_key
ALGORITHM = settings.crypto_algorithm
ACCESS_TOKEN_EXPIRES_SECONDS = settings.access_token_expire_seconds

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="users/token/")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """it verifies validity of hashed_password

    Args:
        plain_password (str): plain password
        hashed_password (str): hashed password

    Returns:
        bool: validity of plain_password
    """
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """it creates hashed password

    Args:
        password (str): plain password

    Returns:
        str: hashed password
    """
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    return encoded_jwt


def process_token(token: str = Depends(oauth2_scheme)) -> schemas.TokenData:
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    username: str = payload.get("sub")
    exp: int = payload.get("exp")

    return schemas.TokenData(username=username, exp=exp)


def get_token(user: schemas.User) -> schemas.Token:
    access_token_expires = timedelta(seconds=ACCESS_TOKEN_EXPIRES_SECONDS)

    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return schemas.Token(access_token=access_token, token_type="bearer")
