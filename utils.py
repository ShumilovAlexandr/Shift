import datetime

from datetime import timedelta
from sqlalchemy import select
from fastapi import (Depends,
                     HTTPException,
                     status)
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer
from jose import (JWTError,
                  jwt)
from pydantic import ValidationError

from config import (ALGORITHM,
                    SECRET_KEY,
                    TIME)
from models.validations import (User,
                                Token,
                                Salary as Sal)
from models.tables import (Users,
                           Salary)
from auth.databes import (get_session,
                          Session,
                          get_connection)


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/login')


# На случай, если захочу получить данные текущего активного пользователя
def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    return AuthService.verify_token(token)


# Для получения зарплатных сведений
def get_current_raise(token: str = Depends(oauth2_scheme)) -> Sal:
    return AuthService.verify_salary(token)


class AuthService:

    @classmethod
    def verify_password(cls, plain_password: str, hashed_password: str) -> \
            bool:
        return pwd_context.verify(plain_password, hashed_password)

    @classmethod
    def get_password_hash(cls, password: str) -> str:
        return pwd_context.hash(password)

    @classmethod
    def verify_token(cls, token: str) -> User:
        """
        Метод, для возвращения данных о текущем активном пользователе и
        передаче в роутер.
        """
        exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Не удалось подтвердить учетные данные',
            headers={
                'WWW-Authenticate': 'Bearer'
            }
        )
        try:
            payload = jwt.decode(
                token,
                SECRET_KEY,
                algorithms=ALGORITHM
            )
        except JWTError:
            raise exception from None
        user_data = payload.get('user')
        try:
            user = User.parse_obj(user_data)
        except ValidationError:
            raise exception from None
        return {'Данные пользователя': user}

    @classmethod
    def verify_salary(cls, token: str) -> Sal:
        """
        Метод, для возвращения данных о зарплате текущего активного
        пользователя и передаче в роутер.
        """
        exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Не удалось подтвердить учетные данные',
            headers={
                'WWW-Authenticate': 'Bearer'
            }
        )
        try:
            payload = jwt.decode(
                token,
                SECRET_KEY,
                algorithms=ALGORITHM
            )
            user_id = payload.get('sub')
            conn = get_connection()
            cur = conn.cursor()
            cur.execute('SELECT * from salary where user_id = %s;',
                        (user_id, ))
            salary_amount = cur.fetchone()
            return {"Зарплатные данные текущего пользователя": {
                'Уникальный идентификатор пользователя': salary_amount[0],
                'Будущая зарплата': salary_amount[1],
                'Дата повышения': salary_amount[2]
            }}
        except JWTError:
            raise exception

    @classmethod
    def create_access_token(cls, user: Users) -> Token:
        """Метод для создания токена."""
        user_data = User.from_orm(user)
        now = datetime.datetime.utcnow()
        dt = now.strftime("%H:%M:%S")
        iat = int(now.timestamp())
        exp = int((now + timedelta(minutes=200)).timestamp())
        payload = {
            'iat': iat,
            'ndf': dt,
            'exp': exp,
            'sub': str(user_data.id),
            'user': user_data.dict()
        }
        token = jwt.encode(
            payload,
            SECRET_KEY,
            algorithm=ALGORITHM
        )
        return Token(access_token=token)

    def __init__(self, session: Session = Depends(get_session)):
        self.session = session

    def authenticate_user(self,
                          login: str,
                          password: str) -> Token:
        exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Некорректный логин или пароль',
            headers={'WWW-Authenticate': 'Bearer'},
        )
        user = (self.session
                .query(Users)
                .filter(Users.login == login)
                .first()
                )
        if not user:
            raise exception
        if not self.verify_password(password, user.password):
            raise exception
        return self.create_access_token(user)
