""" module with all the extra helper functions """

from typing import Optional

from faker import Faker

from server.schemas.users import UserCreate
from server.core.database import SessionLocal
from server.apis.users import (
    create_admin_user,
    get_user_by_email,
    get_user_by_username,
)


faker = Faker()


def generate_user_create_dict() -> dict:
    """it prepares dict with example user created with Faker

    Returns:
        dict: dict with user fields (username, email, password)
    """

    profile = faker.profile()
    return UserCreate(
        username=profile["username"],
        email=profile["mail"],
        password=faker.password(),
    ).dict()


def create_admin(
    username: Optional[str], password: Optional[str], email: Optional[str], session=None
):
    """it creates admin user if given is not created

    Args:
        username (Optional[str]): username of admin user
        password (Optional[str]): password of admin user
        email (Optional[str]): email of admin user
        session ([type], optional): session to create admin user. Defaults to None.
    """
    if not session:
        session = SessionLocal()

    if not get_user_by_username(session, username) and not get_user_by_email(
        session, email
    ):
        create_admin_user(
            session, UserCreate(username=username, password=password, email=email)
        )

    session.close()
