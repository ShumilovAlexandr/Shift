from pydantic import (BaseModel,
                      Field,
                      validator)
from datetime import date


class User(BaseModel):
    """Модель пользователя."""
    id: int
    first_name: str
    second_name: str
    login: str
    password: str

    class Config:
        orm_mode = True


class Salary(BaseModel):
    """Модель сведений о повышении."""
    user_id: int
    salary: int = Field(ge=0)
    next_raise: date


class Token(BaseModel):
    """Модель для токена."""
    access_token: str
    token_type: str = 'Bearer'


