import smtplib
import ssl
import html
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional
from app.config import settings
import logging

logger = logging.getLogger(__name__)


def _build_verification_html(name: str, link: str) -> str:
    safe_name = html.escape(str(name))
    return f"""
    <!DOCTYPE html>
    <html>
    <body style="margin:0;padding:0;background:#0a0a0f;font-family:'Segoe UI',Arial,sans-serif;">
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr><td align="center" style="padding:40px 20px;">
          <table width="560" cellpadding="0" cellspacing="0"
            style="background:linear-gradient(135deg,#0d1117,#161b27);border:1px solid #1e2d45;border-radius:16px;overflow:hidden;">
            <tr>
              <td style="padding:32px;text-align:center;background:linear-gradient(135deg,#0d1b3e,#0a0f1e);">
                <h1 style="margin:0;font-size:28px;color:#00d4ff;letter-spacing:2px;">🛡️ SentinelScan</h1>
                <p style="margin:4px 0 0;color:#8899aa;font-size:13px;">Know Every Vulnerability Before Attackers Do</p>
              </td>
            </tr>
            <tr>
              <td style="padding:40px 32px;">
                <h2 style="color:#e2e8f0;font-size:22px;margin:0 0 16px;">Verify Your Email Address</h2>
                <p style="color:#94a3b8;line-height:1.7;margin:0 0 24px;">
                  Hi <strong style="color:#e2e8f0;">{safe_name}</strong>, thanks for signing up!<br>
                  Click the button below to verify your email address and activate your account.
                </p>
                <div style="text-align:center;margin:32px 0;">
                  <a href="{link}" style="display:inline-block;padding:14px 40px;background:linear-gradient(135deg,#0066ff,#7c3aed);
                    color:#fff;text-decoration:none;border-radius:8px;font-weight:600;font-size:15px;letter-spacing:0.5px;">
                    Verify Email Address
                  </a>
                </div>
                <p style="color:#64748b;font-size:13px;text-align:center;margin:0;">
                  This link expires in 24 hours. If you didn't create an account, you can ignore this email.
                </p>
              </td>
            </tr>
            <tr>
              <td style="padding:20px 32px;border-top:1px solid #1e2d45;text-align:center;">
                <p style="color:#475569;font-size:12px;margin:0;">
                  © 2025 SentinelScan · <a href="{settings.FRONTEND_URL}" style="color:#0066ff;text-decoration:none;">sentinelscan.io</a>
                </p>
              </td>
            </tr>
          </table>
        </td></tr>
      </table>
    </body>
    </html>
    """


def _build_reset_html(name: str, link: str) -> str:
    safe_name = html.escape(str(name))
    return f"""
    <!DOCTYPE html>
    <html>
    <body style="margin:0;padding:0;background:#0a0a0f;font-family:'Segoe UI',Arial,sans-serif;">
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr><td align="center" style="padding:40px 20px;">
          <table width="560" cellpadding="0" cellspacing="0"
            style="background:linear-gradient(135deg,#0d1117,#161b27);border:1px solid #1e2d45;border-radius:16px;overflow:hidden;">
            <tr>
              <td style="padding:32px;text-align:center;background:linear-gradient(135deg,#0d1b3e,#0a0f1e);">
                <h1 style="margin:0;font-size:28px;color:#00d4ff;letter-spacing:2px;">🛡️ SentinelScan</h1>
              </td>
            </tr>
            <tr>
              <td style="padding:40px 32px;">
                <h2 style="color:#e2e8f0;font-size:22px;margin:0 0 16px;">Reset Your Password</h2>
                <p style="color:#94a3b8;line-height:1.7;margin:0 0 24px;">
                  Hi <strong style="color:#e2e8f0;">{safe_name}</strong>,<br>
                  We received a request to reset your SentinelScan password.
                  Click below to set a new password. This link expires in 1 hour.
                </p>
                <div style="text-align:center;margin:32px 0;">
                  <a href="{link}" style="display:inline-block;padding:14px 40px;background:linear-gradient(135deg,#dc2626,#7c3aed);
                    color:#fff;text-decoration:none;border-radius:8px;font-weight:600;font-size:15px;">
                    Reset Password
                  </a>
                </div>
                <p style="color:#64748b;font-size:13px;text-align:center;margin:0;">
                  If you didn't request this, your account is safe — just ignore this email.
                </p>
              </td>
            </tr>
          </table>
        </td></tr>
      </table>
    </body>
    </html>
    """


def _send_email(to_email: str, subject: str, html_body: str) -> bool:
    if not settings.SMTP_USER or not settings.SMTP_PASSWORD:
        logger.warning(f"SMTP not configured — skipping email to {to_email}. Subject: {subject}")
        logger.info(f"[DEV] Email body preview: {html_body[:200]}...")
        return False
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"{settings.SMTP_FROM_NAME} <{settings.SMTP_FROM}>"
        msg["To"] = to_email
        msg.attach(MIMEText(html_body, "html"))
        context = ssl.create_default_context()
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
            server.ehlo()
            server.starttls(context=context)
            server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.sendmail(settings.SMTP_FROM, to_email, msg.as_string())
        return True
    except Exception as e:
        logger.error(f"Failed to send email to {to_email}: {e}")
        return False


async def send_verification_email(to_email: str, name: str, token: str) -> bool:
    link = f"{settings.FRONTEND_URL}/verify-email?token={token}"
    html = _build_verification_html(name, link)
    if settings.DEBUG or settings.SMTP_USER == "your-email@gmail.com":
        logger.info("\n" + "="*50)
        logger.info(f"VERIFICATION LINK FOR {to_email}:")
        logger.info(link)
        logger.info("="*50 + "\n")
    return _send_email(to_email, "Verify your SentinelScan account", html)


async def send_password_reset_email(to_email: str, name: str, token: str) -> bool:
    link = f"{settings.FRONTEND_URL}/reset-password?token={token}"
    html = _build_reset_html(name, link)
    return _send_email(to_email, "Reset your SentinelScan password", html)


async def send_scan_complete_email(to_email: str, name: str, url: str, score: int, report_id: str) -> bool:
    # Strip CR/LF so the subject line can never be used for header injection.
    safe_url = html.escape(str(url).replace("\r", " ").replace("\n", " "))
    link = f"{settings.FRONTEND_URL}/reports/{report_id}"
    grade = "A+" if score >= 90 else "A" if score >= 80 else "B" if score >= 70 else "C" if score >= 60 else "D" if score >= 50 else "F"
    color = "#22c55e" if score >= 70 else "#f59e0b" if score >= 50 else "#ef4444"
    html_body = f"""
    <!DOCTYPE html><html><body style="margin:0;padding:0;background:#0a0a0f;font-family:'Segoe UI',Arial,sans-serif;">
    <table width="100%" cellpadding="0" cellspacing="0">
      <tr><td align="center" style="padding:40px 20px;">
        <table width="560" cellpadding="0" cellspacing="0"
          style="background:linear-gradient(135deg,#0d1117,#161b27);border:1px solid #1e2d45;border-radius:16px;overflow:hidden;">
          <tr><td style="padding:32px;text-align:center;background:linear-gradient(135deg,#0d1b3e,#0a0f1e);">
            <h1 style="margin:0;font-size:28px;color:#00d4ff;">🛡️ SentinelScan</h1>
          </td></tr>
          <tr><td style="padding:40px 32px;text-align:center;">
            <h2 style="color:#e2e8f0;">Scan Complete for {safe_url}</h2>
            <div style="font-size:72px;font-weight:900;color:{color};margin:16px 0;">{grade}</div>
            <div style="font-size:24px;color:{color};margin-bottom:24px;">Security Score: {score}/100</div>
            <a href="{link}" style="display:inline-block;padding:14px 40px;background:linear-gradient(135deg,#0066ff,#7c3aed);
              color:#fff;text-decoration:none;border-radius:8px;font-weight:600;">
              View Full Report →
            </a>
          </td></tr>
        </table>
      </td></tr>
    </table>
    </body></html>
    """
    return _send_email(to_email, f"SentinelScan Report Ready — {safe_url}", html_body)
