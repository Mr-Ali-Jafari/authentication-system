from fastapi import FastAPI
from app.api.login import login
from app.models.models import Base
from app.api.user import user
from app.api.role import role
from app.config.database import database
from app.api.permission import permission


Base.metadata.create_all(bind=database.engine)


app = FastAPI()

@app.on_event("startup")
async def startup_event():
    db = SessionLocal()
    add_user_with_role_and_permission(db, "ali", "ali@admin.com", "12341234", "is_superuser", "create_blog")
    db.close()


app.include_router(login.router)
app.include_router(permission.router)
app.include_router(user.router)
app.include_router(role.router)



