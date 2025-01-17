import re
from os import environ
from typing import List

from passlib.hash import sha256_crypt
from pydantic import BaseModel, validator
from sqlmodel import Session, Field

from src.backend.database import engine
from src.backend.database.orm import User, UserMetadata
from src.backend.routes.nickname_validation import validate_nickname

NICKNAME_PATTERN = re.compile(r"^[a-zA-Z0-9]+$")
PASSWORD_PATTERN = re.compile(r"[0-9]")
FILE_FORMAT = ["image/jpg", "image/png", "image/jpeg"]

EMAIL_PATTERN = re.compile(
    r'^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$')


def get_password_hash(password):
    # using salt from environment variable with 1000 rounds
    # using sha256_crypt
    hashed_pass = sha256_crypt.using(
        rounds=environ.get('ENCRYPT_SALT_ROUNDS'),
        salt=environ.get('ENCRYPT_SALT')
    ).hash(password)

    print(hashed_pass)

    return hashed_pass


def verify_password(password, _hash):
    return sha256_crypt.using(
        rounds=environ.get('ENCRYPT_SALT_ROUNDS'),
        salt=environ.get('ENCRYPT_SALT')
    ).verify(password, _hash)


def validate_photo(content_type, size):
    state = True

    if (content_type not in FILE_FORMAT) or (int(size) > 4194304):
        state = False

    return state


def user_registrate(user_data) -> User:
    new_user = User(
        nickname=user_data.nickname,
        password=user_data.password,
        email=user_data.email
    )

    with Session(engine) as session:
        User.create(new_user, session)

    return new_user


def user_metadata_create(user_data, user_id) -> UserMetadata:
    new_user_metadata = UserMetadata(
        user_id=user_id,
        description=user_data.description,
        photo=user_data.photo
    )

    with Session(engine) as session:
        UserMetadata.create(new_user_metadata, session)

    return new_user_metadata


class Nickname(BaseModel):
    nickname: str | None = Field(None, max_length=20, min_length=3)

    @validator("nickname")
    def validate_name(cls, value):  # Пройдет валидацию при наличии только лишь букв и цифр в нике, а также по длинам.
        if not NICKNAME_PATTERN.search(value):  # Сопоставляю с регулярным выражением

            raise ValueError(
                'Никнейм не соответствует условиям'
            )

        return value


class Credentials(BaseModel):
    password: str
    email: str

    @validator("password")
    def validate_password(cls, value):  # Пройдет валидацию только при наличии цифр, двух букв в разном регистре и
        # по длинам.

        if ((not PASSWORD_PATTERN.search(value))  # Сопоставляю с регулярным выражением
                or (len(value) > 20)
                or (len(value) < 8)
                or (re.sub(PASSWORD_PATTERN, '', value) == '')  # Проверяю наличие букв в пароле
                or (re.sub(PASSWORD_PATTERN, '', value).islower())  # Проверяю наличие заглавных букв
                or (re.sub(PASSWORD_PATTERN, '', value).isupper())  # Проверяю наличие строчных букв
        ):
            raise ValueError(
                'Пароль не соответствует условиям'
            )

        return value

    @validator("email")
    def validate_email(cls, value):
        if not EMAIL_PATTERN.search(value):
            raise ValueError(
                'Email не соответствует условиям')
        return value



class Photo(BaseModel):
    photo: str | None = Field(default=None)


class Description(BaseModel):
    description: str | None = None

    @validator("description")
    def validate_desc(cls, value):  # Пройдет валидацию только по длине.

        if len(value) > 127:
            raise ValueError(
                'Описание профиля не соответствует условиям'
            )

        return value


class Metadata(Photo, Description):
    ...


class UserRequest(Metadata, Nickname, Credentials):
    ...


class UserResponse(Metadata, Nickname):
    id: int


class UserPatchRequest(Nickname):
    nickname: str | None = None
    user_metadata: Metadata


class UserPatchResponse(Nickname):
    nickname: str | None = None
    user_metadata: List[Metadata]
