
import os
from datetime import datetime, timedelta, timezone

import jwt
from jwt.exceptions import InvalidTokenError
from pwdlib import PasswordHash

from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from pydantic import BaseModel, Field

from sqlalchemy import create_engine, Column, Integer, String, select
from sqlalchemy.orm import declarative_base, Session


# 1. DATABASE CONFIGURATION

engine = create_engine(
    "sqlite:///./auth.db",
    connect_args={"check_same_thread": False}
)

Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)


Base.metadata.create_all(bind=engine)


def get_db():
    with Session(engine) as db:
        yield db


# 2. FASTAPI APPLICATION

app = FastAPI(title="FastAPI JWT Authentication Demo")


# 3. CORS CONFIGURATION

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
        "http://localhost:5500",
        "http://127.0.0.1:5500",
        "http://127.0.0.1:8000",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

from dotenv import load_dotenv  # 1. Import the library

# 2. Load the environment variables from the .env file
load_dotenv()
# 4. JWT CONFIGURATION

SECRET_KEY = os.environ["JWT_SECRET_KEY"]
ALGORITHM = "HS256"
TOKEN_EXPIRY_MINUTES = 30

password_hash = PasswordHash.recommended()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


# 5. PYDANTIC SCHEMA

class RegisterUser(BaseModel):
    username: str = Field(min_length=3)
    password: str = Field(min_length=8)


# 6. CREATE JWT TOKEN

def create_access_token(username: str):
    expiry = datetime.now(timezone.utc) + timedelta(
        minutes=TOKEN_EXPIRY_MINUTES
    )

    payload = {
        "sub": username,
        "exp": expiry,
        "password_hash":"nvsnlvsnlvksvns"
    }

    return jwt.encode(
        payload,
        SECRET_KEY,
        algorithm=ALGORITHM
    )


# 7. REGISTER API

@app.post("/register", status_code=201)
def register(data: RegisterUser, db: Session = Depends(get_db)):

    existing_user = db.scalar(
        select(User).where(User.username == data.username)
    )

    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Username already exists"
        )

    new_user = User(
        username=data.username,
        hashed_password=password_hash.hash(data.password)
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {
        "message": "Registration successful",
        "id": new_user.id,
        "username": new_user.username
    }


# 8. LOGIN API

@app.post("/login")
def login(
    form: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    user = db.scalar(
        select(User).where(User.username == form.username)
    )

    if not user or not password_hash.verify(
        form.password, user.hashed_password
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"}
        )

    token = create_access_token(user.username)

    return {
        "access_token": token,
        "token_type": "bearer"
    }


# 9. JWT AUTHENTICATION DEPENDENCY

def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    error = HTTPException(
        status_code=401,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"}
    )

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        username = payload.get("sub")

        if not username:
            raise error

    except InvalidTokenError:
        raise error

    user = db.scalar(
        select(User).where(User.username == username)
    )

    if not user:
        raise error

    return user


# 10. PROTECTED API

@app.get("/me")
def profile(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "message": "You are authenticated"
    }


# 11. PUBLIC API

@app.get("/public")
def public():
    return {"message": "Anyone can access this endpoint"}
