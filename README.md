## **🔐 Secure Authentication & OTP Verification with FastAPI**

A complete authentication system built with FastAPI, featuring JWT-based login, OAuth2 security, password hashing, email-based OTP verification, and SQLite database integration. This project ensures robust user identity protection and secure token-based access.


**🚀 Features**

🔑 User Registration & Login with JWT tokens

🔒 Password hashing using Passlib (bcrypt)

🕵️ OAuth2 Authentication with scopes (admin/user)

📧 Email-based OTP verification during signup

⏱️ OTP expires in 5 minutes

🗄️ SQLAlchemy ORM with SQLite database

⚙️ Strong configuration via pydantic-settings

🏗️ Modular folder structure for scalability


**🔧 Tech Stack**

| Component          | Library                     |
|-------------------|-----------------------------|
| Backend Framework  | FastAPI                     |
| ORM               | SQLAlchemy                  |
| Password Hashing   | Passlib (bcrypt)            |
| Tokens             | python-jose                 |
| Email              | smtplib                     |
| Validation         | Pydantic v2 (pydantic-settings) |
| Database           | SQLite                      |


**🔐 OTP Flow**
User Signup ➝ OTP sent to email ➝ Validate OTP ➝ Account Activated ➝ Login Enabled

OTP length: 6 digits

Expiry: 5 minutes

Stored securely in DB until verification




