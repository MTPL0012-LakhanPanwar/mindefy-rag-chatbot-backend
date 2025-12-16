from typing import List, Optional, Dict, Any
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig, MessageType
from jinja2 import Environment, FileSystemLoader, select_autoescape
from pathlib import Path

from core.config import settings
from services import users as user_service


class EmailService:
    def __init__(self):
        self.config = ConnectionConfig(
            MAIL_USERNAME=settings.mail_username,
            MAIL_PASSWORD=settings.mail_password,
            MAIL_FROM=settings.mail_from,
            MAIL_FROM_NAME=settings.mail_from_name,
            MAIL_PORT=settings.mail_port,
            MAIL_SERVER=settings.mail_server,
            MAIL_STARTTLS=settings.mail_starttls,
            MAIL_SSL_TLS=settings.mail_ssl_tls,
            USE_CREDENTIALS=settings.use_credentials,
            VALIDATE_CERTS=settings.validate_certs,
        )
        self.fastmail = FastMail(self.config)
        
        # Setup Jinja2 environment for email templates
        template_dir = Path(__file__).parent.parent / "templates" / "email"
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(['html', 'xml'])
        )

    async def send_email(
        self,
        to: List[str],
        subject: str,
        template_name: str,
        template_vars: Dict[str, Any],
        cc: Optional[List[str]] = None,
        bcc: Optional[List[str]] = None
    ) -> bool:
        """Send email using template"""
        try:
            # Render HTML template
            template = self.jinja_env.get_template(f"{template_name}.html")
            html_content = template.render(**template_vars)

            message_data = {
                "subject": subject,
                "recipients": to,
                "body": html_content,
                "subtype": MessageType.html,
            }

            if cc:
                message_data["cc"] = cc
            if bcc:
                message_data["bcc"] = bcc

            message = MessageSchema(**message_data)
            
            await self.fastmail.send_message(message)
            return True
        except Exception as e:
            print(f"Email sending failed: {e}")
            return False

    async def send_user_signup_notification(self, user_data: Dict[str, Any]) -> bool:
        """Send notification to admin when user signs up"""
        # Get admin emails dynamically from database
        admin_emails = await user_service.get_admin_emails()
        
        if not admin_emails:
            print("No admin users found in database")
            return False
            
        subject = f"New User Registration Request - {user_data.get('username')}"
        template_vars = {
            "username": user_data.get("username"),
            "email": user_data.get("email"),
            "user_type": user_data.get("userType", "user"),
            "signup_date": user_data.get("createdAt"),
            "gender": user_data.get("gender"),
            "dob": user_data.get("dob"),
        }
        
        return await self.send_email(
            to=admin_emails,
            subject=subject,
            template_name="user_signup_notification",
            template_vars=template_vars
        )

    async def send_approval_notification(self, user_data: Dict[str, Any], approved: bool) -> bool:
        """Send notification to user about approval/rejection"""
        user_email = user_data.get("email")
        if not user_email:
            return False
            
        if approved:
            subject = "Welcome to Mindefy AI - Your Account Has Been Approved!"
            template_name = "user_approved"
        else:
            subject = "Mindefy AI - Account Registration Update"
            template_name = "user_rejected"
            
        template_vars = {
            "username": user_data.get("username"),
            "email": user_data.get("email"),
            "approved": approved,
        }
        
        return await self.send_email(
            to=[user_email],
            subject=subject,
            template_name=template_name,
            template_vars=template_vars
        )

    async def send_welcome_email(self, user_data: Dict[str, Any]) -> bool:
        """Send welcome email to newly approved user"""
        user_email = user_data.get("email")
        if not user_email:
            return False
            
        subject = "Welcome to Mindefy AI - Start Your Journey!"
        template_vars = {
            "username": user_data.get("username"),
            "email": user_data.get("email"),
        }
        
        return await self.send_email(
            to=[user_email],
            subject=subject,
            template_name="welcome",
            template_vars=template_vars
        )


# Global email service instance
email_service = EmailService()
