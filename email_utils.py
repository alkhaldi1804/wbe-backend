import os
import requests

async def send_verification_email(email: str, token: str, first_name: str):
    print("🔥 Sending email via API to:", email)

    api_key = os.getenv("BREVO_API_KEY")

    url = "https://api.brevo.com/v3/smtp/email"

    link = f"https://api.wbe-tools.online/verify?token={token}"

    headers = {
        "accept": "application/json",
        "api-key": api_key,
        "content-type": "application/json"
    }

    data = {
        "sender": {
            "name": "WBE Security",
            "email": "ak_18112@outlook.com"
        },
        "to": [
            {
                "email": email,
                "name": first_name
            }
        ],
        "subject": "Verify your WBE account",
        "htmlContent": f"""
        <html>
          <body style="font-family: Arial; background:#0f172a; padding:20px; color:white;">
            <div style="max-width:500px;margin:auto;background:rgba(255,255,255,0.05);padding:25px;border-radius:15px;text-align:center;">
              
              <img src="https://api.wbe-tools.online/static/email_logo.jpeg" style="width:80px;margin-bottom:15px;" />

              <h2 style="color:#00C6FF;">Welcome to WBE Tools 🚀</h2>

              <p style="text-align:left;">
                Dear <b>{first_name}</b>,
              </p>

              <p style="text-align:left;">
                Please verify your email by clicking the button below.
              </p>

              <a href="{link}" style="display:inline-block;padding:12px 25px;background:#0072FF;color:white;text-decoration:none;border-radius:20px;">
                Verify Email
              </a>

              <p style="margin-top:20px;">Regards,<br><b>WBE Team</b></p>
            </div>
          </body>
        </html>
        """
    }

    try:
        response = requests.post(url, headers=headers, json=data)
        print("📧 Brevo response:", response.text)
    except Exception as e:
        print("❌ Email error:", str(e))


# -----------------------------
# Reset Password Email (🔥 NEW)
# -----------------------------
async def send_reset_email(email: str, token: str, first_name: str):
    print("🔥 Sending RESET email via API to:", email)

    api_key = os.getenv("BREVO_API_KEY")

    url = "https://api.brevo.com/v3/smtp/email"

    link = f"https://api.wbe-tools.online/#/reset-password?token={token}"

    headers = {
        "accept": "application/json",
        "api-key": api_key,
        "content-type": "application/json"
    }

    data = {
        "sender": {
            "name": "WBE Security",
            "email": "ak_18112@outlook.com"
        },
        "to": [
            {
                "email": email,
                "name": first_name
            }
        ],
        "subject": "Reset your password",
        "htmlContent": f"""
        <html>
          <body style="font-family: Arial; background:#0f172a; padding:20px; color:white;">
            <div style="max-width:500px;margin:auto;background:rgba(255,255,255,0.05);padding:25px;border-radius:15px;text-align:center;">
              
              <img src="https://api.wbe-tools.online/static/email_logo.jpeg" style="width:80px;margin-bottom:15px;" />

              <h2 style="color:#00C6FF;">Reset Password 🔐</h2>

              <p style="text-align:left;">
                Hello <b>{first_name}</b>,
              </p>

              <p style="text-align:left;">
                Click the button below to reset your password.
              </p>

              <a href="{link}" style="display:inline-block;padding:12px 25px;background:#0072FF;color:white;text-decoration:none;border-radius:20px;">
                Reset Password
              </a>

              <p style="margin-top:20px;">If you didn't request this, please ignore this email.</p>

              <p style="margin-top:20px;">Regards,<br><b>WBE Team</b></p>
            </div>
          </body>
        </html>
        """
    }

    try:
        response = requests.post(url, headers=headers, json=data)
        print("📧 Reset Email response:", response.text)
    except Exception as e:
        print("❌ Reset Email error:", str(e))