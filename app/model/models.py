# app/model/models.py

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

    # User becomes verified only after OTP verification
    is_verified = Column(Boolean, default=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now())


class UserTempOTP(Base):
    """
    Temporary table storing signup info + hashed OTP until user verifies.
    After successful verification, this record is deleted.
    """

    __tablename__ = "user_temp_otp"

    id = Column(Integer, primary_key=True, index=True)

    username = Column(String(128), nullable=False)
    phone_number = Column(String(32), nullable=True)
    softvence_designation = Column(String(128), nullable=True)

    email = Column(String(256), unique=True, index=True, nullable=False)

    # Temporary hashed password (until verified)
    hashed_password = Column(String, nullable=False)

    # Store hashed OTP
    otp_hash = Column(String, nullable=False)

    # OTP expiration timestamp
    otp_expires_at = Column(DateTime(timezone=False), nullable=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
