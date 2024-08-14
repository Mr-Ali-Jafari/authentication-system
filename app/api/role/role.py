from fastapi import APIRouter, Depends, HTTPException,status
from sqlalchemy.orm import Session
from typing import List
from app.utils.auth_jwt import *
from app.models import models as models
from app.schemas import schemas as schemas
from app.config.database.database import get_db

from app.api.login.login import get_current_user



router = APIRouter(
    prefix="/role",
    tags=['role']
)


@router.post("/roles/", response_model=schemas.Role)
def create_role(role: schemas.RoleCreate, db: Session = Depends(get_db), current_user: schemas.User = Depends(get_current_user)):
    if any(role.name != 'is_superuser' for role in current_user.roles):
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

@router.get("/roles/", response_model=List[schemas.Role])
def read_roles(skip: int = 0, limit: int = 10, db: Session = Depends(get_db), current_user: schemas.User = Depends(get_current_user)):
    if any(role.name != 'is_superuser' for role in current_user.roles):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail='Access denied: You do not have permission to view users'
        )
    roles = db.query(models.Role).offset(skip).limit(limit).all()
    return roles

@router.get("/roles/{role_id}", response_model=schemas.Role)
def read_role(role_id: int, db: Session = Depends(get_db), current_user: schemas.User = Depends(get_current_user)):
    if any(role.name != 'is_superuser' for role in current_user.roles):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail='Access denied: You do not have permission to view users'
        )
    role = db.query(models.Role).filter(models.Role.id == role_id).first()
    if role is None:
        raise HTTPException(status_code=404, detail="Role not found")
    return role