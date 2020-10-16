""" module with security configuration and helper functions """

from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
from jose import jwt
from passlib.context import CryptContext

from server.core.settings import settings
from server.core import schemas

# to get a string like this run:
# openssl rand -hex 32
secret_key = settings.secret_key
algorithm = settings.crypto_algorithm
access_token_expire_minutes = settings.access_token_expire_seconds

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="users/token/")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, secret_key, algorithm=algorithm)

    return encoded_jwt


def process_token(token: str = Depends(oauth2_scheme)) -> schemas.TokenData:
    payload = jwt.decode(token, secret_key, algorithms=[algorithm])
    username: str = payload.get("sub")

    return schemas.TokenData(username=username)


def get_token(user: schemas.User) -> schemas.Token:
    access_token_expires = timedelta(minutes=access_token_expire_minutes)

    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return schemas.Token(access_token=access_token, token_type="bearer")
