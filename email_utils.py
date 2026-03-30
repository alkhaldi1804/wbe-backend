from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from pydantic import EmailStr
import os

conf = ConnectionConfig(
    MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
    MAIL_PASSWORD=os.getenv("MAIL_PASSWORD"),
    MAIL_FROM=os.getenv("MAIL_FROM"),

    MAIL_PORT=587,
    MAIL_SERVER="smtp-relay.brevo.com",

    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=True
)

async def send_verification_email(email: EmailStr, token: str, first_name: str):
    link = f"https://api.wbe-tools.online/verify?token={token}"

    html = f"""
    <html>
      <body style="font-family: Arial; background:#0f172a; padding:20px; color:white;">
        <div style="max-width:500px;margin:auto;background:rgba(255,255,255,0.05);padding:25px;border-radius:15px;text-align:center;">
          
          <img src="https://api.wbe-tools.online/static/email_logo.jpeg" style="width:80px;margin-bottom:15px;" />

          <h2 style="color:#00C6FF;">Welcome to WBE Tools 🚀</h2>

          <p style="text-align:left;">
            Dear <b>{first_name}</b>,
          </p>

          <p style="text-align:left;line-height:1.6;">
            Thank you for joining <b>WBE Cybersecurity Tools</b>.<br><br>
            Please verify your email by clicking the button below.
          </p>

          <a href="{link}" 
             style="display:inline-block;margin-top:20px;padding:12px 25px;background:linear-gradient(90deg,#0072FF,#00C6FF);color:white;text-decoration:none;border-radius:25px;font-weight:bold;">
             Verify Email
          </a>

          <p style="font-size:13px;margin-top:25px;color:#ccc;">
            If you did not create this account, ignore this email.
          </p>

          <hr style="margin:25px 0;border-color:rgba(255,255,255,0.1);" />

          <p style="text-align:left;">
            Regards,<br>
            <b>WBE Security Team</b>
          </p>

        </div>
      </body>
    </html>
    """

    message = MessageSchema(
        subject="Verify your WBE account",
        recipients=[email],
        body=html,
        subtype="html"
    )

    fm = FastMail(conf)
    await fm.send_message(message)
