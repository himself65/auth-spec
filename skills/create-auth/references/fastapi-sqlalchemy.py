# Reference: FastAPI + SQLAlchemy + PostgreSQL
# This shows the complete auth implementation pattern for Python/FastAPI.

# --- models.py ---
import uuid
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String, func
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, unique=True, nullable=False)
    name = Column(String, nullable=True)
    email_verified = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)

    accounts = relationship("Account", back_populates="user")
    sessions = relationship("Session", back_populates="user")


class Session(Base):
    __tablename__ = "sessions"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    token = Column(String, unique=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)

    user = relationship("User", back_populates="sessions")


class Account(Base):
    __tablename__ = "accounts"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    provider_id = Column(String, nullable=False)
    password_hash = Column(String, nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)

    user = relationship("User", back_populates="accounts")


# --- schemas.py ---
from pydantic import BaseModel, EmailStr


class SignUpRequest(BaseModel):
    email: EmailStr
    password: str
    name: str | None = None


class SignInRequest(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: str
    email: str
    name: str | None

    model_config = {"from_attributes": True}


class AuthResponse(BaseModel):
    user: UserResponse
    token: str


class SessionResponse(BaseModel):
    user: UserResponse
    expires_at: datetime


# --- routes.py ---
import secrets
from datetime import datetime, timedelta, timezone

import bcrypt
from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter(prefix="/api/auth")

SESSION_DURATION = timedelta(days=7)


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(12)).decode()


def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


@router.post("/sign-up", response_model=AuthResponse)
async def sign_up(req: SignUpRequest, db: AsyncSession = Depends(get_db)):
    if len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    # Always hash password to prevent timing-based email enumeration
    hashed = hash_password(req.password)

    user = User(email=req.email, name=req.name)
    account = Account(
        user_id=user.id,
        provider_id="credential",
        password_hash=hashed,
    )
    token = secrets.token_hex(32)
    session = Session(
        user_id=user.id,
        token=token,
        expires_at=datetime.now(timezone.utc) + SESSION_DURATION,
    )

    try:
        db.add_all([user, account, session])
        await db.commit()
        await db.refresh(user)
    except Exception:
        await db.rollback()
        # Unique constraint violation (duplicate email) — return fake success
        # to prevent email enumeration. The dummy token won't resolve to a session.
        return AuthResponse(
            user=UserResponse(id=str(uuid.uuid4()), email=req.email, name=req.name),
            token=secrets.token_hex(32),
        )

    return AuthResponse(
        user=UserResponse.model_validate(user),
        token=token,
    )


@router.post("/sign-in", response_model=AuthResponse)
async def sign_in(req: SignInRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == req.email))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    result = await db.execute(
        select(Account).where(
            Account.user_id == user.id,
            Account.provider_id == "credential",
        )
    )
    account = result.scalar_one_or_none()

    if not account or not account.password_hash:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not verify_password(req.password, account.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = secrets.token_hex(32)
    session = Session(
        user_id=user.id,
        token=token,
        expires_at=datetime.now(timezone.utc) + SESSION_DURATION,
    )
    db.add(session)
    await db.commit()

    return AuthResponse(
        user=UserResponse.model_validate(user),
        token=token,
    )


@router.get("/session", response_model=SessionResponse)
async def get_session(
    authorization: str = Header(...),
    db: AsyncSession = Depends(get_db),
):
    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(status_code=401, detail="Unauthorized")

    result = await db.execute(select(Session).where(Session.token == token))
    session = result.scalar_one_or_none()

    if not session or session.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Unauthorized")

    result = await db.execute(select(User).where(User.id == session.user_id))
    user = result.scalar_one()

    return SessionResponse(
        user=UserResponse.model_validate(user),
        expires_at=session.expires_at,
    )


@router.post("/sign-out")
async def sign_out(
    authorization: str = Header(default=""),
    db: AsyncSession = Depends(get_db),
):
    token = authorization.removeprefix("Bearer ").strip()
    if token:
        result = await db.execute(select(Session).where(Session.token == token))
        session = result.scalar_one_or_none()
        if session:
            await db.delete(session)
            await db.commit()

    return {"success": True}
