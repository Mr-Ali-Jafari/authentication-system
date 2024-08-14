from fastapi import FastAPI, Depends, HTTPException,status
from sqlalchemy.orm import Session
from typing import List
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from auth import *
from database import SessionLocal, engine
import models, schemas
from models import Base
import logging
Base.metadata.create_all(bind=engine)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
app = FastAPI()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


#authentication sec


def authenticate_user(db: Session, username: str, password: str):
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

@app.post("/token", response_model=schemas.Token)
def login_for_access_token(db: Session = Depends(get_db), form_data: OAuth2PasswordRequestForm = Depends()):
    try:
        user = authenticate_user(db, form_data.username, form_data.password)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.username}, expires_delta=access_token_expires
        )
        return {"access_token": access_token, "token_type": "bearer"}
    
    except Exception as e:
        # چاپ کردن پیام خطا
        logging.error(f"An error occurred: {str(e)}")
        # بازگشت یک پاسخ Internal Server Error
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"{e}"
        )



def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    payload = decode_access_token(token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = db.query(models.User).filter(models.User.username == payload.get("sub")).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user



# end section

@app.get("/")
def index():
    return {
        'message':' hello if you developer go to http://127.0.0.1:8000/docs'
    }

@app.post("/permissions/", response_model=schemas.Permission)
def create_permission(permission: schemas.PermissionCreate, db: Session = Depends(get_db), current_user: schemas.User = Depends(get_current_user)):
    if not any(role.name == 'is_superuser' for role in current_user.roles):
        raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail='Access denied: You do not have permission to view users'
    )
    db_permission = models.Permission(name=permission.name)
    db.add(db_permission)
    db.commit()
    db.refresh(db_permission)
    return db_permission

@app.get("/permissions/", response_model=List[schemas.Permission])
def read_permissions(skip: int = 0, limit: int = 10, db: Session = Depends(get_db), current_user: schemas.User = Depends(get_current_user)):
    if not any(role.name == 'is_superuser' for role in current_user.roles):
        raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail='Access denied: You do not have permission to view users'
    )
    
    permissions = db.query(models.Permission).offset(skip).limit(limit).all()
    return permissions

@app.get("/permissions/{permission_id}", response_model=schemas.Permission)
def read_permission(permission_id: int, db: Session = Depends(get_db), current_user: schemas.User = Depends(get_current_user)):
    if not any(role.name == 'is_superuser' for role in current_user.roles):
        raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail='Access denied: You do not have permission to view users'
    )
    permission = db.query(models.Permission).filter(models.Permission.id == permission_id).first()
    if permission is None:
        raise HTTPException(status_code=404, detail="Permission not found")
    return permission

@app.post("/roles/", response_model=schemas.Role)
def create_role(role: schemas.RoleCreate, db: Session = Depends(get_db), current_user: schemas.User = Depends(get_current_user)):
    if not any(role.name == 'is_superuser' for role in current_user.roles):
        raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail='Access denied: You do not have permission to view users'
    )
    db_role = models.Role(name=role.name)
    for permission_id in role.permission_ids:
        permission = db.query(models.Permission).filter(models.Permission.id == permission_id).first()
        if permission:
            db_role.permissions.append(permission)
    db.add(db_role)
    db.commit()
    db.refresh(db_role)
    return db_role

@app.get("/roles/", response_model=List[schemas.Role])
def read_roles(skip: int = 0, limit: int = 10, db: Session = Depends(get_db), current_user: schemas.User = Depends(get_current_user)):
    if not any(role.name == 'is_superuser' for role in current_user.roles):
        raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail='Access denied: You do not have permission to view users'
    )
    roles = db.query(models.Role).offset(skip).limit(limit).all()
    return roles

@app.get("/roles/{role_id}", response_model=schemas.Role)
def read_role(role_id: int, db: Session = Depends(get_db), current_user: schemas.User = Depends(get_current_user)):
    if not any(role.name == 'is_superuser' for role in current_user.roles):
        raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail='Access denied: You do not have permission to view users'
    )
    role = db.query(models.Role).filter(models.Role.id == role_id).first()
    if role is None:
        raise HTTPException(status_code=404, detail="Role not found")
    return role

@app.post("/users/", response_model=schemas.User)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db), current_user: schemas.User = Depends(get_current_user)):
    if not any(role.name == 'is_superuser' for role in current_user.roles):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail='Access denied: You do not have permission to view users'
        )
    
    hashed_password = get_password_hash(user.password)
    
    db_user = models.User(
        username=user.username, 
        email=user.email, 
        hashed_password=hashed_password  
    )
    
    for role_id in user.role_ids:
        role = db.query(models.Role).filter(models.Role.id == role_id).first()
        if role:
            db_user.roles.append(role)
    
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user





# Users list
@app.get("/users/", response_model=List[schemas.User])
def read_users(skip: int = 0, limit: int = 10, db: Session = Depends(get_db), current_user: schemas.User = Depends(get_current_user)):
    if not any(role.name == 'is_superuser' for role in current_user.roles):
        raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail='Access denied: You do not have permission to view users'
    )
    
    try:
        users = db.query(models.User).offset(skip).limit(limit).all()
        return users
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred."
        )
# End list




@app.get("/users/{user_id}", response_model=schemas.User)
def read_user(user_id: int, db: Session = Depends(get_db), current_user: schemas.User = Depends(get_current_user)):
    if not any(role.name == 'is_superuser' for role in current_user.roles):
        raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail='Access denied: You do not have permission to view users'
    )
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@app.put("/users/{user_id}", response_model=schemas.User)
def update_user(user_id: int, user: schemas.UserCreate, db: Session = Depends(get_db), current_user: schemas.User = Depends(get_current_user)):
    if not any(role.name == 'is_superuser' for role in current_user.roles):
        raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail='Access denied: You do not have permission to view users'
    )
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    db_user.username = user.username
    db_user.email = user.email
    db_user.hashed_password = user.password  

    db_user.roles = []  
    for role_id in user.role_ids:
        role = db.query(models.Role).filter(models.Role.id == role_id).first()
        if role:
            db_user.roles.append(role)

    db.commit()
    db.refresh(db_user)
    return db_user