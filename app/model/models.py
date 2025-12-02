from sqlalchemy import Column, Integer, String, Boolean, DateTime, func
from ..data.db import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(128), nullable=False)
    phone_number = Column(String(32), nullable=True)
    softvence_designation = Column(String(128), nullable=True)
    email = Column(String(256), unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)
    is_verified = Column(Boolean, default=False)             # <- new
    otp_code = Column(String(256), nullable=True)            # <- store hashed otp
    otp_expires_at = Column(DateTime(timezone=False), nullable=True)  # <- when OTP expires
    created_at = Column(DateTime(timezone=True), server_default=func.now())
