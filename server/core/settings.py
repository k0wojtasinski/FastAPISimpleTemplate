""" module with pydantic BaseSettings object """
from pydantic import BaseSettings


class Settings(BaseSettings):
    host = "0.0.0.0"
    port = 3000
    secret_key = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"  # example value, will be replaced
    crypto_algorithm = "HS256"
    access_token_expire_seconds = 1800
    database_url = "sqlite://"

    class Config:
        case_sensitive = False
        env_prefix = "BACKEND_"


settings = Settings()
