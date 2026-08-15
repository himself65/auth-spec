# Reference: FastAPI + SQLAlchemy + PostgreSQL
# This shows the complete auth implementation pattern for Python/FastAPI.

# --- models.py ---
import uuid
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String, UniqueConstraint, func
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, unique=True, nullable=False)
    name = Column(String, nullable=True)
    image = Column(String, nullable=True)
    email_verified = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)

    accounts = relationship("Account", back_populates="user")
    sessions = relationship("Session", back_populates="user")
    verification_tokens = relationship("VerificationToken", back_populates="user")


class Session(Base):
    __tablename__ = "sessions"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    token = Column(String, unique=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    ip_address = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)

    user = relationship("User", back_populates="sessions")


class Account(Base):
    __tablename__ = "accounts"
    __table_args__ = (UniqueConstraint("provider_id", "account_id"),)

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    provider_id = Column(String, nullable=False)
    account_id = Column(String, nullable=False)
    password_hash = Column(String, nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)

    user = relationship("User", back_populates="accounts")


class VerificationToken(Base):
    __tablename__ = "verification_tokens"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    # "verify-email" or "password-reset" — one table, two flows, and the purpose is
    # matched at redemption so a reset link cannot pass as an email confirmation
    purpose = Column(String, nullable=False)
    # The address the token was issued for, so a later address change cannot
    # inherit the proof
    email = Column(String, nullable=False)
    # SHA-256 of the raw token; the raw value exists only inside the emailed link
    token_hash = Column(String, unique=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    consumed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)

    user = relationship("User", back_populates="verification_tokens")


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


class VerifyEmailSendRequest(BaseModel):
    email: EmailStr


class VerifyEmailConfirmRequest(BaseModel):
    token: str


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirmRequest(BaseModel):
    token: str
    password: str


class StatusResponse(BaseModel):
    success: bool


# --- routes.py ---
import hashlib
import secrets
from datetime import datetime, timedelta, timezone

import bcrypt
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter(prefix="/api/auth")

SESSION_DURATION = timedelta(days=7)
VERIFY_EMAIL_DURATION = timedelta(hours=24)
PASSWORD_RESET_DURATION = timedelta(minutes=30)

# Absolute base URL for the links we email. Configure it — never derive it from the
# request host, which the caller controls.
APP_BASE_URL = "https://example.com"


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(12)).decode()


def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def send_verification_link(email: str, purpose: str, token: str) -> None:
    # This reference ships no mail transport: replace the body below with a real one
    # (SES, Postmark, SMTP) — until you do, nothing is delivered and neither flow can
    # complete. This is the only place the raw token is allowed to exist; the database
    # holds nothing but its SHA-256, and the link must never be logged.
    link = f"{APP_BASE_URL}/{purpose}?token={token}"
    _ = (email, link)  # hand these to the transport you wire in here


async def issue_verification_token(
    db: AsyncSession, user: User, purpose: str, duration: timedelta
) -> None:
    # One outstanding token per purpose — issuing a new one retires the old
    await db.execute(
        delete(VerificationToken).where(
            VerificationToken.user_id == user.id,
            VerificationToken.purpose == purpose,
        )
    )
    raw = secrets.token_hex(32)
    db.add(
        VerificationToken(
            user_id=user.id,
            purpose=purpose,
            email=user.email,
            token_hash=hash_token(raw),
            expires_at=datetime.now(timezone.utc) + duration,
        )
    )
    await db.commit()

    send_verification_link(user.email, purpose, raw)


@router.post("/sign-up", response_model=AuthResponse)
async def sign_up(req: SignUpRequest, request: Request, db: AsyncSession = Depends(get_db)):
    # Normalize email before validation and storage
    email = req.email.strip().lower()

    if len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    # Always hash password to prevent timing-based email enumeration
    hashed = hash_password(req.password)

    # Generate the id up front — SQLAlchemy column defaults only fire at flush,
    # and the account/session rows below need the value now
    user = User(id=str(uuid.uuid4()), email=email, name=req.name)
    # For the credential provider, account_id is the new user's id
    account = Account(
        user_id=user.id,
        provider_id="credential",
        account_id=user.id,
        password_hash=hashed,
    )
    token = secrets.token_hex(32)
    # request.client.host is the direct peer IP; use X-Forwarded-For only behind a trusted proxy
    session = Session(
        user_id=user.id,
        token=token,
        expires_at=datetime.now(timezone.utc) + SESSION_DURATION,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    # Nothing else in a password-only build ever sets email_verified, and a row that
    # never proves an identifier is reaped — so sign-up issues the confirmation token
    # in the same write that creates the user
    verification_token = secrets.token_hex(32)
    verification = VerificationToken(
        user_id=user.id,
        purpose="verify-email",
        email=email,
        token_hash=hash_token(verification_token),
        expires_at=datetime.now(timezone.utc) + VERIFY_EMAIL_DURATION,
    )

    try:
        db.add_all([user, account, session, verification])
        await db.commit()
        await db.refresh(user)
    except Exception:
        await db.rollback()
        # Unique constraint violation (duplicate email) — return fake success
        # to prevent email enumeration. The dummy token won't resolve to a session.
        return AuthResponse(
            user=UserResponse(id=str(uuid.uuid4()), email=email, name=req.name),
            token=secrets.token_hex(32),
        )

    # Send only after the row is committed, and only for a real sign-up — a duplicate
    # email returns above without mailing the existing account's owner
    send_verification_link(email, "verify-email", verification_token)

    return AuthResponse(
        user=UserResponse.model_validate(user),
        token=token,
    )


@router.post("/sign-in", response_model=AuthResponse)
async def sign_in(req: SignInRequest, request: Request, db: AsyncSession = Depends(get_db)):
    # Normalize email before lookup
    email = req.email.strip().lower()

    result = await db.execute(select(User).where(User.email == email))
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
    # request.client.host is the direct peer IP; use X-Forwarded-For only behind a trusted proxy
    session = Session(
        user_id=user.id,
        token=token,
        expires_at=datetime.now(timezone.utc) + SESSION_DURATION,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
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


@router.post("/verify-email/send", response_model=StatusResponse)
async def send_verify_email(req: VerifyEmailSendRequest, db: AsyncSession = Depends(get_db)):
    # Normalize email before lookup
    email = req.email.strip().lower()

    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    # Rate limit this per address and per IP (3/hour is reasonable) — it sends mail
    # on demand. See the rate-limiting feature.
    if user:
        await issue_verification_token(db, user, "verify-email", VERIFY_EMAIL_DURATION)

    # Same 200 whether or not the address has an account
    return StatusResponse(success=True)


@router.post("/verify-email/confirm", response_model=StatusResponse)
async def confirm_verify_email(req: VerifyEmailConfirmRequest, db: AsyncSession = Depends(get_db)):
    now = datetime.now(timezone.utc)
    token_hash = hash_token(req.token)

    # The purpose is part of the lookup: a password-reset token must not be
    # redeemable as an email confirmation
    result = await db.execute(
        select(VerificationToken).where(
            VerificationToken.token_hash == token_hash,
            VerificationToken.purpose == "verify-email",
        )
    )
    verification = result.scalar_one_or_none()

    if not verification:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    # Consume with one conditional write and check the affected-row count — a
    # find-then-update here is a race, and two requests would both redeem the link
    consumed = await db.execute(
        update(VerificationToken)
        .where(
            VerificationToken.id == verification.id,
            VerificationToken.consumed_at.is_(None),
            VerificationToken.expires_at > now,
        )
        .values(consumed_at=now)
    )

    if consumed.rowcount != 1:
        await db.rollback()
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    # Bind the proof to the address it was made about. email_verified stays out of
    # this guard — the write records a proof and authorizes nothing, so two honest
    # confirms of the same unchanged address must not collide. Zero rows means the
    # address changed after the link went out: discard the proof.
    proved = await db.execute(
        update(User)
        .where(User.id == verification.user_id, User.email == verification.email)
        .values(email_verified=True)
    )

    if proved.rowcount != 1:
        await db.rollback()
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    # No credential strip here: this link was issued by the very sign-up that set the
    # password, so it confirms that password rather than adopting a stranger's
    await db.commit()

    return StatusResponse(success=True)


@router.post("/password-reset/request", response_model=StatusResponse)
async def request_password_reset(req: PasswordResetRequest, db: AsyncSession = Depends(get_db)):
    # Normalize email before lookup
    email = req.email.strip().lower()

    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    # Rate limit this per address and per IP (3/hour is reasonable) — it sends mail
    # on demand. See the rate-limiting feature.
    if user:
        await issue_verification_token(db, user, "password-reset", PASSWORD_RESET_DURATION)

    # Same 200 whether or not the address has an account
    return StatusResponse(success=True)


@router.post("/password-reset/confirm", response_model=StatusResponse)
async def confirm_password_reset(
    req: PasswordResetConfirmRequest, db: AsyncSession = Depends(get_db)
):
    # Validate and hash the new password before touching the token — a rejected
    # password must not burn the link, and nothing fallible may sit between the
    # consume and the write that follows it
    if len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    hashed = hash_password(req.password)

    now = datetime.now(timezone.utc)
    token_hash = hash_token(req.token)

    result = await db.execute(
        select(VerificationToken).where(
            VerificationToken.token_hash == token_hash,
            VerificationToken.purpose == "password-reset",
        )
    )
    verification = result.scalar_one_or_none()

    if not verification:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    consumed = await db.execute(
        update(VerificationToken)
        .where(
            VerificationToken.id == verification.id,
            VerificationToken.consumed_at.is_(None),
            VerificationToken.expires_at > now,
        )
        .values(consumed_at=now)
    )

    if consumed.rowcount != 1:
        await db.rollback()
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    # Claim the row if it has never proven mailbox control. email_verified belongs in
    # *this* guard: winning the flip is what authorizes the strip below, and a row
    # that is already verified must never be stripped — its credentials belong to the
    # owner who proved it.
    claimed = await db.execute(
        update(User)
        .where(
            User.id == verification.user_id,
            User.email == verification.email,
            User.email_verified.is_(False),
        )
        .values(email_verified=True)
    )

    if claimed.rowcount == 1:
        # This reset is the first proof of mailbox control the row has ever had, so
        # everything it carries is unproven — a planted password, a planted passkey,
        # a linked provider. Drop every account row, then write the new password into
        # a fresh credential row, since the strip deleted the old one.
        await db.execute(delete(Account).where(Account.user_id == verification.user_id))
        db.add(
            Account(
                user_id=verification.user_id,
                provider_id="credential",
                account_id=verification.user_id,
                password_hash=hashed,
            )
        )
    else:
        # Nothing flipped, which is one of three outcomes: the row is already
        # verified (rotate its password in place), or it is gone, or it now holds a
        # different address and the proof says nothing about it
        result = await db.execute(select(User).where(User.id == verification.user_id))
        user = result.scalar_one_or_none()

        if not user or user.email != verification.email:
            await db.rollback()
            raise HTTPException(status_code=400, detail="Invalid or expired token")

        result = await db.execute(
            select(Account).where(
                Account.user_id == user.id,
                Account.provider_id == "credential",
            )
        )
        account = result.scalar_one_or_none()

        if account:
            account.password_hash = hashed
        else:
            db.add(
                Account(
                    user_id=user.id,
                    provider_id="credential",
                    account_id=user.id,
                    password_hash=hashed,
                )
            )

    # A reset is the remedy for a compromised account: revoke every session so the
    # attacker's does not survive it, and mint none — require a fresh sign-in
    await db.execute(delete(Session).where(Session.user_id == verification.user_id))

    await db.commit()

    return StatusResponse(success=True)
