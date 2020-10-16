""" module with all the extra helper functions """

from faker import Faker

from server.core.schemas import UserCreate

faker = Faker()


def generate_user_create_dict() -> UserCreate:
    profile = faker.profile()
    return UserCreate(
        username=profile["username"],
        email=profile["mail"],
        password=faker.password(),
    ).dict()
