from fastapi import APIRouter,Depends
from sqlalchemy.orm import Session
from app.models.base import get_db
from app.services.login import login_service
from app.models import pydantic 
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/auth/token')


router = APIRouter(
    prefix='/auth',
    tags=['login','auth']
)


@router.post('/token')
def login_route(schema:pydantic.ResponseUser,db: Session = Depends(get_db)):
    return login_service.login_service(db=db,schema=schema)