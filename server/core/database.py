""" module with database settings """

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from server.core.settings import settings


def prepare_engine(database_url: str):
    """It prepares engine for database sessions.
        It provides support for memory-based sqlite database (url=sqlite://)

    Args:
        database_url (str): url of database in a form supported by SQLAlchemy

    Returns:
        engine: SQLAlchemy engine
    """
    if database_url == "sqlite://":
        return create_engine(
            database_url,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
    return create_engine(database_url)


DATABASE_URL = settings.database_url

engine = prepare_engine(DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_session():
    """It yields new session to connect to database.

    Yields:
        session: SQLAlchemy session to connect to database
    """
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
