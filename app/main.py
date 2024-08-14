from fastapi import FastAPI
from app.api.login import login
from app.models.models import Base
from app.api.user import user
from app.api.role import role
from app.config.database import database
from app.api.permission import permission


Base.metadata.create_all(bind=database.engine)


app = FastAPI()

app.include_router(login.router)
app.include_router(permission.router)
app.include_router(user.router)
app.include_router(role.router)



