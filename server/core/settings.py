""" module with pydantic BaseSettings object """
from typing import Optional

from pydantic import BaseSettings


class Settings(BaseSettings):
    """class to provide configuration based on enviroment variables.

    check BaseSettings (https://pydantic-docs.helpmanual.io/usage/settings/) for more information.
    """

    host = "0.0.0.0"
    port = 3000
    secret_key = "09d25e094faa6ca2556c81816"  # example value, will be replaced
    crypto_algorithm = "HS256"
    access_token_expire_seconds = 1800
    database_url = "sqlite://"
    cors_allow_origins = "*"
    cors_allow_headers = "*"
    cors_allow_methods = "*"
    admin_username: Optional[str]
    admin_password: Optional[str]
    admin_email: Optional[str]
    database_connection_string = "sqlite://"

    class Config:
        """ extra configuration for BaseSettings """

        case_sensitive = False
        env_prefix = "BACKEND_"


settings = Settings()
