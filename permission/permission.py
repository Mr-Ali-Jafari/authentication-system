from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from ..auth_jwt import *
from ..models import models as models
from ..schemas import schemas as schemas
from ..database.database import get_db
from ..login.login import get_current_user

router = APIRouter(
    prefix="/permission",
    tags=['permission']
)


@router.post("/permissions/", response_model=schemas.Permission)
def create_permission(permission: schemas.PermissionCreate, db: Session = Depends(get_db), current_user: schemas.User = Depends(get_current_user)):
    if any(role.name == 'create_permission' for role in current_user.roles):
        raise HTTPException(
            status_code=401,
            detail='you don`t have permission for this ',
        )
    db_permission = models.Permission(name=permission.name)
    db.add(db_permission)
    db.commit()
    db.refresh(db_permission)
    return db_permission

@router.get("/permissions/", response_model=List[schemas.Permission])
def read_permissions(skip: int = 0, limit: int = 10, db: Session = Depends(get_db), current_user: schemas.User = Depends(get_current_user)):
    if any(role.name == 'is_superuser' for role in current_user.roles):
        raise HTTPException(
            status_code=401,
            detail='you don`t have permission for this ',
        )
    
    permissions = db.query(models.Permission).offset(skip).limit(limit).all()
    return permissions

@router.get("/permissions/{permission_id}", response_model=schemas.Permission)
def read_permission(permission_id: int, db: Session = Depends(get_db), current_user: schemas.User = Depends(get_current_user)):
    if any(role.name == 'is_superuser' for role in current_user.roles):
        raise HTTPException(
            status_code=401,
            detail='you don`t have permission for this ',
        )
    permission = db.query(models.Permission).filter(models.Permission.id == permission_id).first()
    if permission is None:
        raise HTTPException(status_code=404, detail="Permission not found")
    return permission