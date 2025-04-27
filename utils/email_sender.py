import os
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger(__name__)

class EmailSender:
    """Utility class for sending emails"""
    
    def __init__(self):
        # Get email configuration from environment variables
        self.smtp_server = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
        self.smtp_port = int(os.environ.get('SMTP_PORT', 587))
        self.smtp_username = os.environ.get('SMTP_USERNAME', '')
        self.smtp_password = os.environ.get('SMTP_PASSWORD', '')
        self.from_email = os.environ.get('FROM_EMAIL', 'noreply@zamuunanalysis.com')
        self.use_tls = os.environ.get('SMTP_USE_TLS', 'true').lower() == 'true'
        
        # Flag to determine if email sending is configured
        self.is_configured = bool(self.smtp_username and self.smtp_password)
    
    def send_email(self, to_email, subject, html_content, text_content=None):
        """Send an email with HTML and optional plain text content"""
        if not self.is_configured:
            logger.warning("Email sending not configured. Set SMTP environment variables.")
            return False
            
        try:
            # Create message
            message = MIMEMultipart('alternative')
            message['Subject'] = subject
            message['From'] = self.from_email
            message['To'] = to_email
            
            # Add plain text version if provided, or generate from HTML
            if text_content is None:
                # Simple conversion from HTML to text (not perfect)
                text_content = html_content.replace('<br>', '\n').replace('</p>', '\n\n')
                text_content = ''.join(c for c in text_content if c not in '<>{}/')
            
            # Attach parts
            message.attach(MIMEText(text_content, 'plain'))
            message.attach(MIMEText(html_content, 'html'))
            
            # Connect to server and send
            if self.use_tls:
                server = smtplib.SMTP(self.smtp_server, self.smtp_port)
                server.starttls()
            else:
                server = smtplib.SMTP_SSL(self.smtp_server, self.smtp_port)
                
            server.login(self.smtp_username, self.smtp_password)
            server.sendmail(self.from_email, to_email, message.as_string())
            server.quit()
            
            logger.info(f"Email sent successfully to {to_email}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email: {str(e)}")
            return False
            
    def send_password_reset(self, to_email, username, temp_password):
        """Send a password reset email with a temporary password"""
        subject = "Your Password Reset Request - Zamuun Analysis Dashboard"
        
        html_content = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background-color: #0066B3; color: white; padding: 10px; text-align: center; }}
                .content {{ padding: 20px; }}
                .footer {{ text-align: center; margin-top: 20px; font-size: 12px; color: #666; }}
                .password {{ font-family: monospace; font-size: 20px; background-color: #f4f4f4; 
                          padding: 10px; margin: 15px 0; border: 1px solid #ddd; text-align: center; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h2>Password Reset</h2>
                </div>
                <div class="content">
                    <p>Hello {username},</p>
                    <p>We received a request to reset your password for the Zamuun Analysis Dashboard.</p>
                    <p>Your temporary password is:</p>
                    <div class="password">{temp_password}</div>
                    <p>Please use this temporary password to log in. You will be prompted to set a new password immediately after logging in.</p>
                    <p>If you did not request a password reset, please contact your administrator immediately.</p>
                    <p>Best regards,<br>The Zamuun Analysis Team</p>
                </div>
                <div class="footer">
                    This is an automated message, please do not reply.
                </div>
            </div>
        </body>
        </html>
        """
        
        return self.send_email(to_email, subject, html_content)

# Create a singleton instance for easy access
email_sender = EmailSender() 