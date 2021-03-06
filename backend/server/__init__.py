""" module with server """

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from server.routes import users
from server.core.database import engine
from server.models import Base
from server.core.settings import settings
from server.core.utils import create_admin

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Backend", description="This is backend for")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allow_origins.split(","),
    allow_methods=settings.cors_allow_methods.split(","),
    allow_headers=settings.cors_allow_headers.split(","),
)

app.include_router(users.router)

if settings.admin_username:
    create_admin(
        username=settings.admin_username,
        password=settings.admin_password,
        email=settings.admin_email,
    )
