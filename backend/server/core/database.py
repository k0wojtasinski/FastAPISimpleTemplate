""" module with database settings """

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from retrying import retry

from server.core.settings import settings

CONNECTION_STRING = settings.database_connection_string
MAX_TIMEOUT = settings.max_timeout_in_seconds


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


@retry(wait_exponential_multiplier=1000, wait_exponential_max=MAX_TIMEOUT)
def prepare_local_session(engine):
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)


engine = prepare_engine(CONNECTION_STRING)

SessionLocal = prepare_local_session(engine)


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
