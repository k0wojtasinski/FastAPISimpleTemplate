""" module with pydantic BaseSettings object """
from typing import Optional

from pydantic import BaseSettings


class Settings(BaseSettings):
    """class to provide configuration based on enviroment variables.

    check BaseSettings (https://pydantic-docs.helpmanual.io/usage/settings/) for more information.
    """

    host: str
    port: int
    secret_key: str
    crypto_algorithm = "HS256"
    access_token_expire_seconds: int
    cors_allow_origins: str
    cors_allow_headers: str
    cors_allow_methods: str
    admin_username: Optional[str]
    admin_password: Optional[str]
    admin_email: Optional[str]
    database_connection_string = "sqlite://"

    class Config:
        """ extra configuration for BaseSettings """

        case_sensitive = False
        env_prefix = "BACKEND_"


settings = Settings()
