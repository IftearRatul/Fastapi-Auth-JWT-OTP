# 🔐 FastAPI Authentication & Authorization System  
A complete authentication system built with **FastAPI**, **SQLite**, and **JWT**, featuring:

- User Registration  
- Email Verification with OTP  
- Login with JWT  
- Forgot Password (OTP-based)  
- Reset Password  
- Secure Password Hashing  
- Modular Clean Architecture  

---

## 🚀 Features

✔ User Signup  
✔ Email Verification (OTP)  
✔ Login with JWT Access Token  
✔ Forgot Password (OTP-based)  
✔ Reset Password  
✔ SQLite Database  
✔ SQLAlchemy ORM  
✔ Modular Folder Structure  
✔ Easy to Extend (admin roles, profile, refresh token, etc.)  

## 📬 API Endpoints

| **Method** | **Endpoint** | **Description** |
|------------|--------------|------------------|
| **POST** | `/auth/signup` | Register new user & send OTP |
| **POST** | `/auth/verify-email` | Verify signup OTP |
| **POST** | `/auth/login` | Login using email & password |
| **POST** | `/auth/forgot-password` | Request OTP for password reset |
| **POST** | `/auth/reset-password` | Verify OTP and set a new password |

## 🔒 Security Design

- Passwords hashed using bcrypt
- OTP hashed before storing
- OTP expires automatically
- JWT tokens used for authentication
- Email must be verified before login
