from os import environ

from fastapi import APIRouter
from fastapi import Depends, Response
from fastapi.exceptions import HTTPException
from fastapi.security import HTTPBasicCredentials, HTTPBasic
from pydantic import BaseModel
from sqlmodel import Session

from src.backend.database import engine
from src.backend.database.orm import User
from src.backend.dependencies import cookie, backend, verifier
from src.backend.internals.users import get_password_hash
from src.backend.sessions import SessionData

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
import jwt

app = APIRouter()
security = HTTPBasic()


class UserAuth(BaseModel):
    nickname = str
    password = str


def verify_credentials(nickname: str, password: str) -> User | HTTPException:
    with Session(engine) as session:
        user = User.get_by_nickname(session, nickname)
        if user is None:
            return HTTPException(status_code=401, detail="Invalid username or password")
        if get_password_hash(password) != user.password:
            return HTTPException(status_code=401, detail="Invalid username or password")

    return user


def send_mail(your_message: str, mail_to: str, mail_subject: str):
    msg = MIMEMultipart()

    password = environ.get("MAIL_PASS")
    msg['From'] = f'Vlada Galimova <{environ.get("MAIL_FROM")}>'
    msg['To'] = mail_to
    msg['Subject'] = mail_subject

    msg.attach(MIMEText(your_message, 'plain'))
    
    server = smtplib.SMTP('smtp.yandex.com', 587)
    # server = smtplib.SMTP('smtp.gmail.com', 587)
    # server = smtplib.SMTP("smtp.mail.yahoo.com", 587)

    server.starttls()
    server.login(environ.get("MAIL_FROM"), password)

    server.sendmail(msg['From'], msg['To'], msg.as_string())

    server.quit()


SECRET_KEY = "secret-key"
ALGORITHM = "HS256"


def create_token(user_id: int, user_nickname: str) -> str:
    created_at = datetime.now()
    expires_at = created_at + timedelta(minutes=5)
    token_data = {"user_id": user_id, "user_nickname": user_nickname, "exp": expires_at}
    token = jwt.encode(token_data, SECRET_KEY, algorithm=ALGORITHM)
    return token


def validate_token(token: str) -> dict | HTTPException:
    try:
        token_data = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])  # Декодирование JWT-токена
        return token_data
    # Блок исключений для обработки ошибок при декодировании JWT-токена. Произойдет ошибка - возвращается HTTPException
    except jwt.PyJWTError:
        return HTTPException(status_code=401, detail="Invalid authentication credentials")


@app.post("/login", dependencies=[Depends(cookie.get_last_cookie)])
async def login(
        credentials: HTTPBasicCredentials = Depends(security),
        old_session: SessionData | None = Depends(verifier.get_last_session),
):
    if old_session is not None:
        return {"message": "Already logged in"}

    user = verify_credentials(credentials.username, credentials.password)

    if isinstance(user, HTTPException):
        raise user

    code = create_token(user.id, user.nickname)

    send_mail(f"Ваш код для входа ActNow: {code}\n"
              f"Для подтверждения перейдите по ссылке: http://127.0.0.1:8000/confirm?code={code}",
              mail_to=user.email, mail_subject="ActNow")

    return {"success": True, 'message': "Проверьте почту"}


@app.get("/confirm", dependencies=[Depends(cookie.get_last_cookie)])
async def check_code(code: str, response: Response, old_session: SessionData | None = Depends(verifier.get_last_session)):
    if old_session is not None:
        return {"message": "Already logged in"}

    token_data = validate_token(code)

    if isinstance(token_data, HTTPException):
        raise token_data

    session = SessionData(user_id=token_data['user_id'], nickname=token_data['user_nickname'])

    await backend.create(session.uuid, session)

    cookie.attach_to_response(response, session.uuid)

    return {"success": True}
