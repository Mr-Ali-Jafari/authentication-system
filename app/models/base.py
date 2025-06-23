from fastapi import FastAPI, Depends,HTTPException
from sqlalchemy import create_engine,Column,Integer,String
import sqlalchemy
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel
import sqlalchemy.orm

DATABASE_URL = 'sqlite:///../test.db'
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autoflush=False,bind=engine)
Base = sqlalchemy.orm.declarative_base() 

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class Users(Base):
    __tablename__ = 'users'
    id = Column(Integer,index=True,primary_key=True)
    username = Column(String,index=True)
    email = Column(String,index=True)
    password = Column(String)