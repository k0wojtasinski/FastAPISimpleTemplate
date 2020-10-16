from fastapi import FastAPI

from server.routes import users
from server.core.database import engine
from server.core.models import Base

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Backend", description="This is backend for")

app.include_router(users.router)
