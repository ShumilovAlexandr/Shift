from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
)

Base = declarative_base()


class Users(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    first_name = Column(String)
    second_name = Column(String)
    login = Column(String, nullable=False, unique=True)
    password = Column(String, nullable=False)


class Salary(Base):
    __tablename__ = 'salary'

    user_id = Column(Integer, ForeignKey('users.id'), primary_key=True)
    salary = Column(Integer, nullable=False)
    next_raise = Column(DateTime)

