from app.services.register import register_service
from fastapi import APIRouter,Depends
from app.models.base import Session,get_db
from app.models.pydantic import CreateUser as cuser
router = APIRouter(
    prefix='/auth',
    tags=['register','auth']
)


@router.post('/register')
def register_route(schemas: cuser,db: Session = Depends(get_db)):
    return register_service.cuser_service(user=schemas,db=db)