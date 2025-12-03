# app/services/verification_service.py
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import secrets

from app.model.models import Verification, User
from app.schemas.user import UserCreate
from app.utils.security import pwd_context, hash_password
from app.utils.email_utils import send_email
from app.config import settings
from fastapi import HTTPException, status

OTP_LENGTH = 6

def _generate_numeric_otp(length: int = OTP_LENGTH) -> str:
    digits = "0123456789"
    return "".join(secrets.choice(digits) for _ in range(length))

def get_verification_by_email(db: Session, email: str):
    return db.query(Verification).filter(Verification.email == email).first()

def create_temp_user(db: Session, user_in: UserCreate, otp_length: int = OTP_LENGTH):
    # Check email not already used in real users
    from app.services.user_service import get_user_by_email as get_real_user
    if get_real_user(db, user_in.email):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

    # Optional: allow overwrite of existing verification? here we disallow duplicate
    if get_verification_by_email(db, user_in.email):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="A verification already exists for this email. Please verify or request resend.")

    otp = _generate_numeric_otp(otp_length)
    otp_hash = pwd_context.hash(otp)
    expire_at = datetime.utcnow() + timedelta(minutes=settings.OTP_EXPIRE_MINUTES)

    temp = Verification(
        username=user_in.username,
        phone_number=user_in.phone_number,
        softvence_designation=user_in.softvence_designation,
        email=user_in.email,
        hashed_password=hash_password(user_in.password),
        otp_hash=otp_hash,
        otp_expires_at=expire_at
    )
    db.add(temp)
    db.commit()
    db.refresh(temp)

    # send OTP email (plaintext OTP to user)
    subject = "Your verification OTP"
    body = f"Hello {temp.username},\n\nYour verification code is: {otp}\nIt expires in {settings.OTP_EXPIRE_MINUTES} minutes.\n\nIf you didn't request this, ignore."
    send_email(temp.email, subject, body)

    return {"msg": "verification created; OTP sent"}

def resend_otp(db: Session, email: str, otp_length: int = OTP_LENGTH):
    temp = get_verification_by_email(db, email)
    if not temp:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No verification request found")
    otp = _generate_numeric_otp(otp_length)
    temp.otp_hash = pwd_context.hash(otp)
    temp.otp_expires_at = datetime.utcnow() + timedelta(minutes=settings.OTP_EXPIRE_MINUTES)
    db.add(temp)
    db.commit()
    db.refresh(temp)

    subject = "Your verification OTP (resent)"
    body = f"Hello {temp.username},\n\nYour new verification code is: {otp}\nIt expires in {settings.OTP_EXPIRE_MINUTES} minutes."
    send_email(temp.email, subject, body)
    return {"msg": "otp resent"}

def verify_and_promote(db: Session, email: str, otp: str):
    temp = get_verification_by_email(db, email)
    if not temp:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Verification not found")

    # check expiry
    if datetime.utcnow() > temp.otp_expires_at:
        db.delete(temp)
        db.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OTP expired; request a new one")

    # verify OTP using passlib
    if not pwd_context.verify(otp, temp.otp_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid OTP")

    # create real user
    user = User(
        username=temp.username,
        phone_number=temp.phone_number,
        softvence_designation=temp.softvence_designation,
        email=temp.email,
        hashed_password=temp.hashed_password,
        is_active=True,
        is_superuser=False,
        is_verified=True
    )
    db.add(user)
    # delete temp record
    db.delete(temp)
    db.commit()
    db.refresh(user)

    return user

def cleanup_expired_verifications(db: Session):
    """Optional: delete expired verification records."""
    now = datetime.utcnow()
    expired = db.query(Verification).filter(Verification.otp_expires_at < now).all()
    for rec in expired:
        db.delete(rec)
    db.commit()
