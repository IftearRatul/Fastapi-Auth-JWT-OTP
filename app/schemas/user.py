# app/schemas/user.py
from pydantic import BaseModel, EmailStr, Field

class UserBase(BaseModel):
    username: str
    email: EmailStr
    phone_number: str | None = None
    softvence_designation: str | None = None

class UserCreate(UserBase):
    password: str = Field(..., max_length=72)  # bcrypt limit

class UserOut(UserBase):
    id: int
    is_active: bool
    is_superuser: bool
    is_verified: bool

    model_config = {"from_attributes": True}  # pydantic v2: use from_attributes

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    sub: str | None = None
    scopes: list[str] = []

class OTPVerify(BaseModel):
    email: EmailStr
    otp: str = Field(..., min_length=4, max_length=10)

class ResendOTP(BaseModel):
    email: EmailStr
