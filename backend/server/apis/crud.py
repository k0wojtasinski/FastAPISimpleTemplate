""" module with crud functions to standardize database manipulation """

from typing import Optional, Union

from pydantic import BaseModel

from sqlalchemy.orm import Session

from server.models import Base


def get_first_model(
    session: Session, model_class: Base, predicate=None
) -> Optional[Base]:
    """it gets first item of given model from the database, supports SQLAlchemy predicate

    Args:
        session (Session): connection to database
        model_class (Base): SQLAlchemy model class
        predicate: predicate to filter query (e.g. id [model.id == id])

    Returns:
        Optional[Base]: first item or None
    """
    return session.query(model_class).filter(predicate).first()


def get_all_models(
    session: Session, model_class: Base, skip: int, limit: int, predicate=None
) -> list[Base]:
    """it gets all the items of given model, can skip and limit it, supports SQLAlchemy predicate
    Args:
        session (Session): connection to database
        model_class (Base): SQLAlchemy model class
        skip (int): parameter to skip first n items
        limit (int): parameter to limit read items to n
        predicate: predicate to filter query (e.g. id [model.id == id])

    Returns:
        list[Base]: list of items (can be empty)
    """
    if predicate:
        return (
            session.query(model_class).filter(predicate).offset(skip).limit(limit).all()
        )

    return session.query(model_class).offset(skip).limit(limit).all()


def create_model(
    session: Session, schema: Union[dict, BaseModel], model_class: Base
) -> Base:
    """it creates model into the database, based on schema

    Args:
        session (Session): connection to database
        schema (Union[dict, BaseModel]): schema of item
        model_class (Base): SQLAlchemy model class

    Returns:
        Base: created item
    """
    if not isinstance(schema, dict):
        schema = schema.dict()

    model = model_class(**schema)

    session.add(model)
    session.commit()
    session.refresh(model)

    return model


def update_model(session: Session, model: Base) -> Base:
    """it updates given item in the database

    Args:
        session (Session): connection to database
        model (Base): item to be updated
    Returns:
        Base: updated item
    """
    session.commit()
    session.refresh(model)

    return model


def delete_model(session: Session, model: Base):
    """it deletes given item from the database

    Args:
        session (Session): connection to the database
        model (Base): model to be deleted
    """
    session.delete(model)
    session.commit()
