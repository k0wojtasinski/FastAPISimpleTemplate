""" module with security configuration and helper functions """

from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from fastapi.security.oauth2 import get_authorization_scheme_param
from jose import jwt
from passlib.context import CryptContext

from server.core.settings import settings
from server.schemas.users import AccessToken, RefreshToken, TokenData, UserSchema


SECRET_KEY = settings.secret_key
ALGORITHM = settings.crypto_algorithm
ACCESS_TOKEN_EXPIRES_SECONDS = settings.access_token_expire_seconds
REFRESH_TOKEN_EXPIRES_SECONDS = settings.refresh_token_expire_seconds

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class OAuth2PasswordBearerCookieBased(OAuth2PasswordBearer):
    """ this is custom implementation of OAuth2PasswordBearer to check cookies """

    async def __call__(self, request: Request) -> Optional[str]:
        authorization: str = request.cookies.get("Authorization")

        scheme, param = get_authorization_scheme_param(authorization)
        if not authorization or scheme.lower() != "bearer":
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            return None
        return param


oauth2_scheme_access_token = OAuth2PasswordBearer(tokenUrl="users/token/")
oauth2_scheme_refresh_token = OAuth2PasswordBearerCookieBased(tokenUrl="users/token/")


class CredentialsException(HTTPException):
    """ it is raised when provided credentials are wrong """

    def __init__(self, detail: str):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            headers={"WWW-Authenticate": "Bearer"},
        )


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


def create_access_token(data: dict) -> str:
    """it decodes given data to create access token.
        it calls create_token method

    Args:
        data (dict): data to be included in token.

    Returns:
        str: decoded token
    """
    return create_token(data, timedelta(seconds=ACCESS_TOKEN_EXPIRES_SECONDS))


def create_refresh_token(data: dict) -> str:
    """it decodes given data to create refresh token.
        it calls create_token method
    Args:
        data (dict): data to be included in token.

    Returns:
        str: decoded token
    """
    return create_token(data, timedelta(seconds=REFRESH_TOKEN_EXPIRES_SECONDS))


def create_token(data: dict, expires_delta: timedelta) -> str:
    """it decodes given data to create token.
        it uses SECRET_KEY provided in settings
        it is called by more specific functions

    Args:
        data (dict): data to be included in token.z
        expires_delta (timedelta): expiration time of token (in seconds).

    Returns:
        str: decoded token
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    return encoded_jwt


def process_access_token(
    access_token: str = Depends(oauth2_scheme_access_token),
) -> TokenData:
    """it decodes provided access token and returns its content.

    Args:
        access_token (str): access token provided by the client
        (see oauth2_scheme_access_token for more info)

    Returns:
        TokenData: token data in a friendly format.
    """
    payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
    username: str = payload.get("sub")
    exp: int = payload.get("exp")

    return TokenData(username=username, exp=exp)


def process_refresh_token(
    refresh_token: str = Depends(oauth2_scheme_refresh_token),
) -> TokenData:
    """it decodes provided refresh token and returns its content.

    Args:
        refresh_token (str): resfresh token provided by the client
        (see oauth2_scheme_refresh_token for more info)

    Returns:
        TokenData: token data in a friendly format.
    """
    payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
    username: str = payload.get("sub")
    exp: int = payload.get("exp")

    return TokenData(username=username, exp=exp)


def get_access_token(user: UserSchema) -> AccessToken:
    """gets access token based on given user.

        It calls create_access_token.

    Args:
        user (UserSchema): user to get token for

    Returns:
        AccessToken: desired token
    """
    access_token = create_access_token(data={"sub": user.username})
    return AccessToken(access_token=access_token, token_type="bearer")


def get_refresh_token(user: UserSchema) -> RefreshToken:
    """gets refresh token based on given user.

        It calls create_refresh_token.

    Args:
        user (UserSchema): user to get token for

    Returns:
        RefreshToken: desired token
    """

    refresh_token = create_refresh_token(data={"sub": user.username})

    return RefreshToken(refresh_token=refresh_token, token_type="bearer")
