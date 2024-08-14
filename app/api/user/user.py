from fastapi import APIRouter, Depends, HTTPException,status
from sqlalchemy.orm import Session
from typing import List
from app.utils.auth_jwt.auth import *
from app.models import models as models
from app.schemas import schemas as schemas
from app.api.login.login import get_current_user
import logging
from app.config.database.database import get_db
router = APIRouter(
    prefix="/user",
    tags=['user']
)


@router.post("/users/", response_model=schemas.User)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db), current_user: schemas.User = Depends(get_current_user)):
    if any(role.name != 'is_superuser' for role in current_user.roles):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail='Access denied: You do not have permission to view users'
        )
    db_user = models.User(username=user.username, email=user.email, hashed_password=user.password)  # هش کردن پسورد در عمل توصیه می‌شود
    for role_id in user.role_ids:
        role = db.query(models.Role).filter(models.Role.id == role_id).first()
        if role:
            db_user.roles.append(role)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user





# Users list
@router.get("/users/", response_model=List[schemas.User])
def read_users(skip: int = 0, limit: int = 10, db: Session = Depends(get_db), current_user: schemas.User = Depends(get_current_user)):
    if any(role.name != 'is_superuser' for role in current_user.roles):
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




@router.get("/users/{user_id}", response_model=schemas.User)
def read_user(user_id: int, db: Session = Depends(get_db), current_user: schemas.User = Depends(get_current_user)):
    if any(role.name != 'is_superuser' for role in current_user.roles):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail='Access denied: You do not have permission to view users'
        )
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@router.put("/users/{user_id}", response_model=schemas.User)
def update_user(user_id: int, user: schemas.UserCreate, db: Session = Depends(get_db), current_user: schemas.User = Depends(get_current_user)):
    if any(role.name != 'is_superuser' for role in current_user.roles):
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