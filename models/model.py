import datetime

from sqlalchemy import (MetaData,
                        Table,
                        Column,
                        Integer,
                        String,
                        ForeignKey,
                        DateTime)


metadata = MetaData()

users = Table(
    'users',
    metadata,
    Column('id', Integer, primary_key=True),
    Column('first_name', String),
    Column('second_name', String),
    Column('login', String, nullable=False, unique=True),
    Column('password', String, nullable=False)
)


salary = Table(
    'salary',
    metadata,
    Column('user_id', Integer, ForeignKey('users.id')),
    Column('salary', Integer, nullable=False),
    Column('next_raise', DateTime)
)
