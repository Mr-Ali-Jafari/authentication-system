from fastapi import FastAPI

from .login import login
from .models.models import Base
from .user import user
from .role import role
from .database import database
from .permission import permission
# Start App
Base.metadata.create_all(bind=database.engine)


app = FastAPI()

app.include_router(login.router)
app.include_router(permission.router)
app.include_router(user.router)
app.include_router(role.router)



