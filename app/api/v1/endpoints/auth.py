# app/api/v1/endpoints/auth.py
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.data.db import get_db
from app.services.user_service import create_user, authenticate_user, verify_otp_for_email, resend_otp
from app.schemas.user import UserCreate, Token, OTPVerify, ResendOTP
from app.utils.security import create_access_token
from typing import Dict

router = APIRouter(tags=["auth"], prefix="/api/v1/auth")

@router.post("/signup", response_model=Dict[str, str])
def signup(user_in: UserCreate, db: Session = Depends(get_db)):
    """
    Signup: creates user and sends OTP to email. Login is allowed only after email verification.
    """
    user = create_user(db, user_in)
    return {"msg": "user created; OTP sent to email"}

@router.post("/verify-email", response_model=Dict[str, str])
def verify_email(payload: OTPVerify, db: Session = Depends(get_db)):
    """
    Verify email by OTP. JSON: {"email":"...","otp":"123456"}
    """
    user = verify_otp_for_email(db, payload.email, payload.otp)
    return {"msg": "email verified"}

@router.post("/resend-otp", response_model=Dict[str, str])
def resend(payload: ResendOTP, db: Session = Depends(get_db)):
    resend_otp(db, payload.email)
    return {"msg": "otp resent"}

@router.post("/login", response_model=Token)
def login(payload: Dict[str, str], db: Session = Depends(get_db)):
    """
    Expects JSON: {"email":"...","password":"..."}
    """
    email = payload.get("email")
    password = payload.get("password")
    if not email or not password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email and password required")
    user = authenticate_user(db, email, password)
    scopes = ["admin"] if user.is_superuser else ["user"]
    access_token = create_access_token(subject=str(user.id), scopes=scopes)
    return {"access_token": access_token, "token_type": "bearer"}
