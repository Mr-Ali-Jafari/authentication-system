from app.models.base import BaseModel


class CreateUser(BaseModel):
    username: str
    email: str
    password: str

class ResponseUser(BaseModel):
    username: str
    password: str