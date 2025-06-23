from fastapi import FastAPI
from app.models.base import Base,engine
from app.routes.register import reg_route
from app.routes.login import login_route
app = FastAPI()

Base.metadata.create_all(bind=engine)


app.include_router(reg_route.router)
app.include_router(login_route.router)

@app.get('/')
def main():
    return {
        'status_code':200
    }