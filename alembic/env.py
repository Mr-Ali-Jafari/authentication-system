from __future__ import absolute_import
import os
import sys
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import DeclarativeMeta
from alembic import context
from sqlalchemy.orm import sessionmaker
from models import Base  # Import your models here

# این آبجکت Config از فایل .ini Alembic برای دسترسی به مقادیر موجود است
config = context.config

# تفسیر فایل پیکربندی برای لاگینگ
from logging.config import fileConfig
fileConfig(config.config_file_name)

# اضافه کردن MetaData مدل‌ها برای پشتیبانی از 'autogenerate'
target_metadata = Base.metadata

def run_migrations_offline():
    """اجرای مایگریشن‌ها در حالت 'آفلاین'."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(url=url, target_metadata=target_metadata, literal_binds=True)

    with context.begin_transaction():
        context.run_migrations()

def run_migrations_online():
    """اجرای مایگریشن‌ها در حالت 'آنلاین'."""
    engine = create_engine(config.get_main_option("sqlalchemy.url"))
    connection = engine.connect()
    context.configure(connection=connection, target_metadata=target_metadata)

    with context.begin_transaction():
        context.run_migrations()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
