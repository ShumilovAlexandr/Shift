from fastapi import (FastAPI,
                     APIRouter,
                     Depends,
                     HTTPException)
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import insert

from models.model import (users,
                          salary)
from models.validations import (User,
                                Salary,
                                Token)
from auth.databes import (Session,
                          get_session)
from utils import (AuthService,
                   get_current_raise)


router = APIRouter(
    prefix='/salary'
)
app = FastAPI()


@app.post('/signup', response_model=User)
def create_new_user(user: User, session: Session = Depends(get_session)):
    """Добавление нового пользователя."""
    user = {
       'id': user.id,
       'first_name': user.first_name,
       'second_name': user.second_name,
       'login': user.login,
       'password': AuthService.get_password_hash(user.password)
    }
    if user:
        stmt = insert(users).values(user)
        session.execute(stmt)
        session.commit()
        return user
    else:
        raise HTTPException(status_code=400, detail="Что-то с запросом!")


@app.post('/salary', response_model=Salary)
def add_raise(sal: Salary, session: Session = Depends(get_session)):
    """Добавление данных о зп и о повышении."""
    salar = {
        'user_id': sal.user_id,
        'salary': sal.salary,
        'next_raise': sal.next_raise
    }
    if salar:
        stmt = insert(salary).values(salar)
        session.execute(stmt)
        session.commit()
        return salar
    else:
        raise HTTPException(status_code=400, detail="Что-то с запросом!")


@app.post('/login', response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(),
          auth_service: AuthService = Depends(),
          ):
    """Возвращает функцию создания токена."""
    return auth_service.authenticate_user(
        form_data.username,
        form_data.password
    )


@app.get('/salary')
def get_info_about_salary(salar: Salary = Depends(get_current_raise)):
    """Возвращает информацию о будущей зп и повышении."""
    return salar

