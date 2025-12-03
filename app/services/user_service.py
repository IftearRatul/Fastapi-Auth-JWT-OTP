# app/services/user_service.py

from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import secrets

from fastapi import HTTPException, status
from app.model.models import User, UserTempOTP
from app.schemas.user import UserCreate
from app.utils.security import hash_password, verify_password, pwd_context
from app.config import settings
from app.utils.email_utils import send_email


# ----------------------------------------
# GET USER HELPERS
# ----------------------------------------

def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()


def get_user(db: Session, user_id: int):
    return db.query(User).filter(User.id == user_id).first()


# ----------------------------------------
# AUTHENTICATE USER
# ----------------------------------------

def authenticate_user(db: Session, email: str, password: str):
    user = get_user_by_email(db, email)
    if not user:
        return None

    if not verify_password(password, user.hashed_password):
        return None

    if not user.is_verified:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail="Email not verified"
        )

    return user


# ----------------------------------------
# CREATE USER + SEND OTP
# ----------------------------------------

def create_user(db: Session, user_in: UserCreate, is_superuser: bool = False):
    if get_user_by_email(db, user_in.email):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )

    new_user = User(
        username=user_in.username,
        email=user_in.email,
        phone_number=user_in.phone_number,
        softvence_designation=user_in.softvence_designation,
        hashed_password=hash_password(user_in.password),
        is_superuser=is_superuser,
        is_verified=False
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # SEND OTP
    generate_and_send_otp(db, new_user)

    return new_user


# ----------------------------------------
# OTP GENERATION
# ----------------------------------------

def _generate_numeric_otp(length: int = 6):
    digits = "0123456789"
    return "".join(secrets.choice(digits) for _ in range(length))


def generate_and_send_otp(db: Session, user: User, otp_length: int = 6):
    otp = _generate_numeric_otp(otp_length)
    otp_hash = pwd_context.hash(otp)

    expire_at = datetime.utcnow() + timedelta(
        minutes=settings.OTP_EXPIRE_MINUTES
    )

    # DELETE previous OTP for this email
    db.query(UserTempOTP).filter(UserTempOTP.email == user.email).delete()

    # CREATE new OTP entry
    otp_entry = UserTempOTP(
        username=user.username,
        phone_number=user.phone_number,
        softvence_designation=user.softvence_designation,
        email=user.email,
        hashed_password=user.hashed_password,
        otp_hash=otp_hash,
        otp_expires_at=expire_at
    )

    db.add(otp_entry)
    db.commit()

    # SEND EMAIL
    subject = "Your Email Verification Code"
    body = (
        f"Hello {user.username},\n\n"
        f"Your OTP is: {otp}\n"
        f"It will expire in {settings.OTP_EXPIRE_MINUTES} minutes.\n\n"
        f"If this wasn't you, please ignore this email."
    )

    send_email(user.email, subject, body)


# ----------------------------------------
# VERIFY OTP
# ----------------------------------------

def verify_otp_for_email(db: Session, email: str, otp: str):
    temp_otp = db.query(UserTempOTP).filter(
        UserTempOTP.email == email
    ).first()

    if not temp_otp:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="No OTP found for this email"
        )

    # CHECK expiration
    if datetime.utcnow() > temp_otp.otp_expires_at:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="OTP expired"
        )

    # VERIFY OTP
    if not pwd_context.verify(otp, temp_otp.otp_hash):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="Invalid OTP"
        )

    # GET actual user
    user = get_user_by_email(db, email)
    if not user:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # MARK verified
    user.is_verified = True
    db.add(user)

    # REMOVE temporary OTP entry
    db.query(UserTempOTP).filter(
        UserTempOTP.email == email
    ).delete()

    db.commit()
    db.refresh(user)

    return user


# ----------------------------------------
# RESEND OTP
# ----------------------------------------

def resend_otp(db: Session, email: str):
    user = get_user_by_email(db, email)
    if not user:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    generate_and_send_otp(db, user)

    return {"message": "OTP resent successfully"}
