""" module with all the extra helper functions """

from typing import Optional

from faker import Faker

from server.core.schemas import UserCreate
from server.core.database import SessionLocal
from server.apis.users import (
    create_admin_user,
    read_user_by_email,
    read_user_by_username,
)

faker = Faker()


def generate_user_create_dict() -> UserCreate:
    profile = faker.profile()
    return UserCreate(
        username=profile["username"],
        email=profile["mail"],
        password=faker.password(),
    ).dict()


def create_admin(
    username: Optional[str], password: Optional[str], email: Optional[str], session=None
):
    if not session:
        session = SessionLocal()

    if not read_user_by_username(session, username) and not read_user_by_email(
        session, email
    ):
        return create_admin_user(
            session, UserCreate(username=username, password=password, email=email)
        )

    session.close()
