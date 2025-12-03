# app/utils/security.py
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt
from jose.exceptions import JWTError, ExpiredSignatureError
from passlib.context import CryptContext

from ..config import settings
from ..schemas.user import TokenData

# === Password hashing context ===
# Using bcrypt here (passlib + bcrypt). If you want Argon2, replace with "argon2"
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

# === OAuth2 scheme (used by dependencies) ===
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/api/v1/auth/login",
    scopes={"user": "Normal user", "admin": "Admin user"}
)

# === Password helpers ===
def hash_password(password: str) -> str:
    """
    Hash a plaintext password (or OTP) using the shared pwd_context.
    """
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    """
    Verify a plaintext secret against a hashed value.
    """
    return pwd_context.verify(plain, hashed)


# === JWT helpers ===
def create_access_token(
    subject: str,
    scopes: Optional[List[str]] = None,
    expires_delta: Optional[timedelta] = None
) -> str:
    """
    Create a signed JWT access token.

    subject: typically the user id or email (string)
    scopes: list of scope strings included in token
    expires_delta: optional timedelta to override default expiry
    """
    to_encode = {"sub": subject}
    if scopes:
        to_encode["scopes"] = scopes

    expire = datetime.utcnow() + (
        expires_delta if expires_delta else timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode["exp"] = expire
    to_encode["iat"] = datetime.utcnow()

    token = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return token


def decode_access_token(token: str) -> TokenData:
    """
    Decode and validate a JWT access token and return TokenData
    (raises HTTPException on failure).
    """
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        sub = payload.get("sub")
        scopes = payload.get("scopes", [])

        if sub is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token missing subject"
            )

        return TokenData(sub=str(sub), scopes=scopes)

    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired"
        )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )
