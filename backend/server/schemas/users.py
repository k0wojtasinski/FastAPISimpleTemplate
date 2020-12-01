""" module with all the users schemas """

from typing import Optional
from pydantic import BaseModel, EmailStr


class UserBase(BaseModel):
    """ base User schema. """

    username: str
    email: EmailStr


class UserCreate(UserBase):
    """ schema to create User requests. """

    password: str


class UserSchema(UserBase):
    """ full User schema, to be mapped into User model. """

    id: int
    is_active: bool
    is_admin: bool

    class Config:
        """ configuration for User schema. """

        orm_mode = True


class AccessToken(BaseModel):
    """token schema.
    Note that token is not saved into database."""

    access_token: str
    token_type: str


class RefreshToken(BaseModel):
    refresh_token: str
    token_type: str


class UserTokens(BaseModel):
    access_token: AccessToken
    refresh_token: RefreshToken


class TokenData(BaseModel):
    """ user-friendly token data schema. """

    username: Optional[str]
    exp: Optional[int]


class PasswordUpdate(BaseModel):
    """schema to update password.
    Note that password update is provided by dedicated endpoint."""

    password: str
