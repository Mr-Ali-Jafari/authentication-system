from app.tools import jwt
from app.models.base import Users as Muser
from app.models.pydantic import CreateUser as cuserschema
from sqlalchemy.orm import Session



def cuser_service(user:cuserschema,db:Session):
    db_user = Muser(username=user.username,email=user.email,password=jwt.get_password_hash(user.password))
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    db.close()
    return db_user

