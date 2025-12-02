# app/utils/email_utils.py
import smtplib
from email.message import EmailMessage
from app.config import settings

def send_email(to_email: str, subject: str, body: str):
    if not settings.SMTP_HOST or not settings.SMTP_USERNAME or not settings.SMTP_PASSWORD:
        # In dev, you may want to print instead of sending
        print("Email not sent (SMTP not configured). Would send to:", to_email)
        print("Subject:", subject)
        print("Body:", body)
        return

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = settings.SMTP_FROM or settings.SMTP_USERNAME
    msg["To"] = to_email
    msg.set_content(body)

    with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
        server.starttls()
        server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
        server.send_message(msg)
