""" tests for users api """
from server.apis import users
from server.schemas.users import UserCreate, PasswordUpdate, UserBase
from server.models.users import User


def test_create_new_user(user_json, test_session):
    """ test to prove that user api can create new user """
    new_user = UserCreate(**user_json)

    created_user = users.create_user(test_session, new_user)

    assert isinstance(created_user, User)
    assert created_user.username == user_json.get("username")
    assert created_user.email == user_json.get("email")
    assert created_user.hashed_password != user_json.get("password")


def test_get_user_by_id(user_json, test_session):
    """ test to prove that users api can get user by id """
    new_user = UserCreate(**user_json)

    created_user = users.create_user(test_session, new_user)

    found_user = users.get_user(test_session, created_user.id)

    assert found_user == created_user
    assert not users.get_user(test_session, created_user.id + 1)


def test_get_user_by_username(user_json, test_session):
    """ test to prove that users api can get user by username """
    new_user = UserCreate(**user_json)

    created_user = users.create_user(test_session, new_user)

    found_user = users.get_user_by_username(test_session, created_user.username)

    assert found_user == created_user
    assert not users.get_user_by_username(test_session, created_user.username[::-1])


def test_get_user_by_email(user_json, test_session):
    """ test to prove that users api can get user by email """
    new_user = UserCreate(**user_json)

    created_user = users.create_user(test_session, new_user)

    found_user = users.get_user_by_email(test_session, created_user.email)

    assert found_user == created_user
    assert not users.get_user_by_username(test_session, created_user.email[::-1])


def test_delete_user(user_json, test_session):
    """ test to prove that user api can delete new user """
    new_user = UserCreate(**user_json)

    created_user = users.create_user(test_session, new_user)

    users.delete_user(test_session, created_user)

    assert not test_session.query(User).filter(User.id == 1).first()
    assert test_session.query(User).count() == 0


def test_update_user(user_json, test_session):
    """ test to prove that user api can update user """
    new_user = UserCreate(**user_json)

    modified_user_schema = UserBase(
        username=user_json.get("username")[::-1], email=f"new{user_json.get('email')}"
    )

    created_user = users.create_user(test_session, new_user)
    updated_user = users.update_user(test_session, created_user, modified_user_schema)

    assert updated_user.username == modified_user_schema.username
    assert updated_user.email == modified_user_schema.email
    assert updated_user.hashed_password == created_user.hashed_password
    assert updated_user.id == created_user.id


def test_update_user_password(user_json, test_session):
    """ test to prove that user api can update password """
    new_user = UserCreate(**user_json)
    created_user = users.create_user(test_session, new_user)

    old_password = created_user.hashed_password

    updated_user = users.update_password(
        test_session,
        created_user,
        PasswordUpdate(password=user_json.get("password")[::-1]),
    )

    assert updated_user.username == created_user.username
    assert updated_user.email == created_user.email
    assert updated_user.hashed_password != old_password
