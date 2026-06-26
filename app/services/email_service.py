import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
import threading
from app.core.config import settings

logger = logging.getLogger(__name__)

def _send_email_sync(to_email: str, username: str):
    # If no SMTP credentials are provided, simulate the output in the log
    if not settings.SMTP_HOST:
        logger.info(f"[EMAIL SIMULATION] Welcome email generated for {to_email} (User: {username})")
        print(f"[EMAIL SIMULATION] Welcome email generated for {to_email} (User: {username})")
        return

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "Welcome to KeyVault - Security & Usage Vault"
        msg["From"] = settings.SMTP_FROM
        msg["To"] = to_email

        text = f"Hello {username},\n\nWelcome to KeyVault! Your account has been successfully registered.\n\nBest,\nThe KeyVault Team"
        html = f"""
        <html>
          <body style="font-family: sans-serif; background-color: #0b0f19; color: #f8fafc; padding: 20px;">
            <div style="max-width: 600px; margin: 0 auto; background-color: #0f172a; border: 1px solid rgba(255,255,255,0.08); border-radius: 12px; padding: 30px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
              <h2 style="color: #8b5cf6; margin-bottom: 20px; font-weight: 700;">Welcome to KeyVault!</h2>
              <p style="color: #e2e8f0; font-size: 1rem; line-height: 1.6;">Hello <strong>{username}</strong>,</p>
              <p style="color: #cbd5e1; font-size: 1rem; line-height: 1.6;">Your KeyVault account has been successfully registered. You can now store your API keys, monitor usage analytics, and run credentials leak scanning.</p>
              <p style="margin-top: 30px; font-size: 0.875rem; color: #94a3b8; border-top: 1px solid rgba(255,255,255,0.08); padding-top: 20px;">
                Best regards,<br>
                <strong>The KeyVault Team</strong>
              </p>
            </div>
          </body>
        </html>
        """
        
        part1 = MIMEText(text, "plain")
        part2 = MIMEText(html, "html")
        msg.attach(part1)
        msg.attach(part2)

        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
            if settings.SMTP_PORT == 587:
                server.starttls()
            if settings.SMTP_USER and settings.SMTP_PASSWORD:
                server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.sendmail(settings.SMTP_FROM, to_email, msg.as_string())
        logger.info(f"Welcome email successfully sent to {to_email}")
        print(f"Welcome email successfully sent to {to_email}")
    except Exception as e:
        logger.error(f"Failed to send welcome email to {to_email}: {str(e)}")
        print(f"Failed to send welcome email to {to_email}: {str(e)}")

def send_welcome_email(to_email: str, username: str):
    """
    Sends a welcome email to the registered user asynchronously.
    """
    thread = threading.Thread(target=_send_email_sync, args=(to_email, username))
    thread.daemon = True
    thread.start()
