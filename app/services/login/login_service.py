from fastapi import Depends, HTTPException, status
from app.models.pydantic import ResponseUser
from app.models.base import Users
from sqlalchemy.orm import Session
from app.tools import jwt
import dotenv, os, datetime

dotenv.load_dotenv(dotenv_path='../../app/')

def auth_user(db: Session, username: str, password: str):
    user = db.query(Users).filter(Users.username == username).first()
    if not user or not jwt.verify_password(password, user.password):
        return {
            'status': status.HTTP_401_UNAUTHORIZED,
            'message': 'رمز یا نام کاربری اشتباه وارد شده است'
        }
    return user

def login_service(db: Session, schema: ResponseUser):
    is_authenticated = auth_user(db=db, username=schema.username, password=schema.password)
    

    if isinstance(is_authenticated, dict):
        return is_authenticated
    
    token_expire = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30)) 
    

    access_token = jwt.create_access_token(
        data={'sub': is_authenticated.username}, 
        expires_delta=datetime.timedelta(minutes=token_expire)
    )

    return {
        'status': status.HTTP_200_OK,
        'token': access_token,  
        'token_type': 'bearer'  
    }


def get_current_user_service(db:Session,token:str):
    current_user = jwt.decode_access_token(token=token)

    if current_user is None:
        return {
            'status':status.HTTP_401_UNAUTHORIZED,
            'message':'ورود غیرمجاز',
        }
    
    user = db.query(Users).filter(Users.username == current_user.get("sub")).first()

    if user is None:
        return {
            'status':status.HTTP_401_UNAUTHORIZED,
            'message':'ورود غیرمجاز',
        }
    
    return user
