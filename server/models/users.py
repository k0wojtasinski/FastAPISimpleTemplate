""" module with all the users models """

from sqlalchemy import Boolean, Column, Integer, String

from server.models import Base


class User(Base):
    """SQLAlchemy model for user.

    It has all the data from User table.

    Note that it should not be used in HTTP responses (see schemas instead).

    id (number): id of user

    username (str): username of user

    email (str): email of user

    hashed_password (str): password in hashed form

    is_active (bool): determines if user is active or not

    is_admin (bool): determines if user is admin or not
    """

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
