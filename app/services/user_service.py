# app/services/user_service.py
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import secrets
from app.model.models import User
from app.schemas.user import UserCreate
from app.utils.security import hash_password, verify_password, pwd_context
from app.config import settings
from app.utils.email_utils import send_email
from fastapi import HTTPException, status

def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()

def get_user(db: Session, user_id: int):
    return db.query(User).filter(User.id == user_id).first()

def create_user(db: Session, user_in: UserCreate, is_superuser: bool = False):
    db_user = get_user_by_email(db, user_in.email)
    if db_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")
    user = User(
        username=user_in.username,
        email=user_in.email,
        phone_number=user_in.phone_number,
        softvence_designation=user_in.softvence_designation,
        hashed_password=hash_password(user_in.password),
        is_superuser=is_superuser,
        is_verified=False  # must verify email first
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    # generate and send OTP
    generate_and_send_otp(db, user)

    return user

def authenticate_user(db: Session, email: str, password: str):
    user = get_user_by_email(db, email)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    if not user.is_verified:
        # deny login until email verified
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Email not verified")
    return user

def _generate_numeric_otp(length: int = 6) -> str:
    # generate a zero-padded numeric OTP
    # use secrets.choice for digits for cryptographic randomness
    digits = "0123456789"
    return "".join(secrets.choice(digits) for _ in range(length))

def generate_and_send_otp(db: Session, user: User, otp_length: int = 6):
    otp = _generate_numeric_otp(otp_length)
    # hash OTP before storing
    otp_hash = pwd_context.hash(otp)
    expire_at = datetime.utcnow() + timedelta(minutes=settings.OTP_EXPIRE_MINUTES)

    user.otp_code = otp_hash
    user.otp_expires_at = expire_at
    db.add(user)
    db.commit()
    db.refresh(user)

    # send email (plain OTP in email)
    subject = "Your verification OTP"
    body = f"Hello {user.username},\n\nYour verification code is: {otp}\nIt expires in {settings.OTP_EXPIRE_MINUTES} minutes.\n\nIf you didn't request this, ignore."
    send_email(user.email, subject, body)

def verify_otp_for_email(db: Session, email: str, otp: str):
    user = get_user_by_email(db, email)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if user.is_verified:
        return user  # already verified

    if not user.otp_code or not user.otp_expires_at:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No OTP found; request a new one")

    if datetime.utcnow() > user.otp_expires_at:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OTP expired; request a new one")

    # verify OTP using passlib context
    if not pwd_context.verify(otp, user.otp_code):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid OTP")

    user.is_verified = True
    # clear OTP fields
    user.otp_code = None
    user.otp_expires_at = None
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

def resend_otp(db: Session, email: str):
    user = get_user_by_email(db, email)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    generate_and_send_otp(db, user)
    return {"msg": "OTP resent"}
