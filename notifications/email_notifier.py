"""
Email notification system for SSL certificate expiration alerts
"""

import smtplib
import ssl
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Dict, Optional
from jinja2 import Template

from database.models import Certificate, CertificateOwnership, NotificationLog, DatabaseManager


class EmailNotifier:
    """Handle email notifications for certificate expiration."""
    
    def __init__(self, config: dict, db_manager: DatabaseManager):
        self.config = config
        self.db_manager = db_manager
        self.email_config = config.get('email', {})
        
        # Email templates
        self.templates = {
            'expiration_warning': self._get_expiration_template(),
            'renewal_success': self._get_renewal_success_template(),
            'renewal_failure': self._get_renewal_failure_template()
        }
    
    def send_expiration_notifications(self, days_before: int) -> Dict:
        """Send expiration notifications for certificates expiring in X days."""
        session = self.db_manager.get_session()
        results = {
            'sent': 0,
            'failed': 0,
            'errors': []
        }
        
        try:
            # Get certificates expiring in specified days
            target_date = datetime.utcnow() + timedelta(days=days_before)
            start_date = target_date - timedelta(days=1)
            
            expiring_certs = session.query(Certificate).filter(
                Certificate.not_valid_after >= start_date,
                Certificate.not_valid_after <= target_date,
                Certificate.is_active == True,
                Certificate.is_expired == False
            ).all()
            
            for cert in expiring_certs:
                try:
                    # Check if notification already sent for this timeframe
                    existing_notification = session.query(NotificationLog).filter(
                        NotificationLog.certificate_id == cert.id,
                        NotificationLog.days_before_expiry == days_before,
                        NotificationLog.status == 'sent'
                    ).first()
                    
                    if existing_notification:
                        continue  # Skip if already notified
                    
                    # Get ownership information
                    ownership = session.query(CertificateOwnership).filter_by(
                        certificate_id=cert.id
                    ).first()
                    
                    if not ownership or not ownership.owner_email:
                        # Log that no email recipient found
                        self._log_notification(session, cert.id, 'email', days_before, 
                                             '', 'No recipient', 'No email address configured', 'failed')
                        continue
                    
                    # Send notification
                    success = self._send_expiration_email(cert, ownership, days_before)
                    
                    if success:
                        results['sent'] += 1
                        self._log_notification(session, cert.id, 'email', days_before,
                                             ownership.owner_email, 
                                             f'Certificate expiring in {days_before} days',
                                             'Email sent successfully', 'sent')
                    else:
                        results['failed'] += 1
                        self._log_notification(session, cert.id, 'email', days_before,
                                             ownership.owner_email,
                                             f'Certificate expiring in {days_before} days',
                                             'Failed to send email', 'failed')
                
                except Exception as e:
                    results['failed'] += 1
                    results['errors'].append(f"Error processing cert {cert.id}: {str(e)}")
                    
                    # Log the error
                    ownership_email = ''
                    try:
                        ownership = session.query(CertificateOwnership).filter_by(
                            certificate_id=cert.id
                        ).first()
                        if ownership:
                            ownership_email = ownership.owner_email or ''
                    except:
                        pass
                    
                    self._log_notification(session, cert.id, 'email', days_before,
                                         ownership_email, 'Error processing notification',
                                         str(e), 'failed')
            
            session.commit()
            
        except Exception as e:
            session.rollback()
            results['errors'].append(f"Database error: {str(e)}")
        finally:
            session.close()
        
        return results
    
    def _send_expiration_email(self, cert: Certificate, ownership: CertificateOwnership, 
                              days_before: int) -> bool:
        """Send expiration warning email for a specific certificate."""
        try:
            # Prepare email content
            subject = f"SSL Certificate Expiring in {days_before} Days - {cert.common_name}"
            
            template_data = {
                'certificate': cert,
                'ownership': ownership,
                'days_before': days_before,
                'expiry_date': cert.not_valid_after.strftime('%Y-%m-%d %H:%M:%S UTC'),
                'common_name': cert.common_name,
                'file_path': cert.file_path,
                'issuer': cert.issuer_info.get('common_name', 'Unknown') if cert.issuer_info else 'Unknown',
                'subject_alt_names': ', '.join(cert.subject_alt_names) if cert.subject_alt_names else 'None'
            }
            
            html_body = self.templates['expiration_warning'].render(**template_data)
            text_body = self._html_to_text(html_body)
            
            # Send email
            return self._send_email(
                to_email=ownership.owner_email,
                subject=subject,
                html_body=html_body,
                text_body=text_body
            )
            
        except Exception as e:
            print(f"Error sending expiration email: {e}")
            return False
    
    def send_renewal_notification(self, cert: Certificate, success: bool, 
                                 message: str = "") -> bool:
        """Send renewal result notification."""
        session = self.db_manager.get_session()
        try:
            ownership = session.query(CertificateOwnership).filter_by(
                certificate_id=cert.id
            ).first()
            
            if not ownership or not ownership.owner_email:
                return False
            
            template_key = 'renewal_success' if success else 'renewal_failure'
            subject_status = 'Successful' if success else 'Failed'
            subject = f"Certificate Renewal {subject_status} - {cert.common_name}"
            
            template_data = {
                'certificate': cert,
                'ownership': ownership,
                'success': success,
                'message': message,
                'common_name': cert.common_name,
                'file_path': cert.file_path
            }
            
            html_body = self.templates[template_key].render(**template_data)
            text_body = self._html_to_text(html_body)
            
            result = self._send_email(
                to_email=ownership.owner_email,
                subject=subject,
                html_body=html_body,
                text_body=text_body
            )
            
            # Log the notification
            self._log_notification(session, cert.id, 'email', 0,
                                 ownership.owner_email, subject, message,
                                 'sent' if result else 'failed')
            session.commit()
            
            return result
            
        except Exception as e:
            session.rollback()
            print(f"Error sending renewal notification: {e}")
            return False
        finally:
            session.close()
    
    def _send_email(self, to_email: str, subject: str, html_body: str, 
                   text_body: str) -> bool:
        """Send an email using SMTP."""
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = self.email_config.get('from_address', self.email_config.get('username'))
            msg['To'] = to_email
            
            # Add text and HTML parts
            text_part = MIMEText(text_body, 'plain')
            html_part = MIMEText(html_body, 'html')
            
            msg.attach(text_part)
            msg.attach(html_part)
            
            # Send email
            smtp_server = self.email_config.get('smtp_server')
            smtp_port = self.email_config.get('smtp_port', 587)
            username = self.email_config.get('username')
            password = self.email_config.get('password')
            use_tls = self.email_config.get('use_tls', True)
            
            if use_tls:
                server = smtplib.SMTP(smtp_server, smtp_port)
                server.starttls(context=ssl.create_default_context())
            else:
                server = smtplib.SMTP_SSL(smtp_server, smtp_port)
            
            server.login(username, password)
            server.send_message(msg)
            server.quit()
            
            return True
            
        except Exception as e:
            print(f"SMTP Error: {e}")
            return False
    
    def _log_notification(self, session, cert_id: int, notification_type: str,
                         days_before: int, recipient: str, subject: str,
                         message: str, status: str):
        """Log notification attempt to database."""
        log_entry = NotificationLog(
            certificate_id=cert_id,
            notification_type=notification_type,
            days_before_expiry=days_before,
            recipient=recipient,
            subject=subject,
            message=message,
            status=status,
            error_message=message if status == 'failed' else None
        )
        session.add(log_entry)
    
    def _get_expiration_template(self) -> Template:
        """Get email template for expiration warnings."""
        template_str = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>SSL Certificate Expiration Warning</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #f44336; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background-color: #f9f9f9; }
        .cert-details { background-color: white; padding: 15px; margin: 10px 0; border-left: 4px solid #f44336; }
        .footer { text-align: center; padding: 20px; font-size: 12px; color: #666; }
        .urgent { color: #f44336; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 SSL Certificate Expiration Warning</h1>
        </div>
        
        <div class="content">
            <p>Hello {{ ownership.owner_username or 'Certificate Owner' }},</p>
            
            <p class="urgent">Your SSL certificate will expire in {{ days_before }} days!</p>
            
            <div class="cert-details">
                <h3>Certificate Details:</h3>
                <ul>
                    <li><strong>Common Name:</strong> {{ common_name }}</li>
                    <li><strong>File Path:</strong> {{ file_path }}</li>
                    <li><strong>Expiry Date:</strong> {{ expiry_date }}</li>
                    <li><strong>Issuer:</strong> {{ issuer }}</li>
                    <li><strong>Subject Alt Names:</strong> {{ subject_alt_names }}</li>
                    {% if ownership.application_name %}
                    <li><strong>Application:</strong> {{ ownership.application_name }}</li>
                    {% endif %}
                    {% if ownership.environment %}
                    <li><strong>Environment:</strong> {{ ownership.environment }}</li>
                    {% endif %}
                </ul>
            </div>
            
            <p><strong>Action Required:</strong> Please renew this certificate before it expires to avoid service disruption.</p>
            
            {% if ownership.owner_url %}
            <p><strong>Related URL:</strong> <a href="{{ ownership.owner_url }}">{{ ownership.owner_url }}</a></p>
            {% endif %}
            
            <p>If you have any questions, please contact your system administrator.</p>
        </div>
        
        <div class="footer">
            <p>This is an automated message from SSL Certificate Manager</p>
            <p>Generated on {{ datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC') }}</p>
        </div>
    </div>
</body>
</html>
        """
        return Template(template_str)
    
    def _get_renewal_success_template(self) -> Template:
        """Get email template for successful renewals."""
        template_str = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>SSL Certificate Renewal Successful</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #4CAF50; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background-color: #f9f9f9; }
        .cert-details { background-color: white; padding: 15px; margin: 10px 0; border-left: 4px solid #4CAF50; }
        .footer { text-align: center; padding: 20px; font-size: 12px; color: #666; }
        .success { color: #4CAF50; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>✅ SSL Certificate Renewal Successful</h1>
        </div>
        
        <div class="content">
            <p>Hello {{ ownership.owner_username or 'Certificate Owner' }},</p>
            
            <p class="success">Your SSL certificate has been successfully renewed!</p>
            
            <div class="cert-details">
                <h3>Certificate Details:</h3>
                <ul>
                    <li><strong>Common Name:</strong> {{ common_name }}</li>
                    <li><strong>File Path:</strong> {{ file_path }}</li>
                    {% if ownership.application_name %}
                    <li><strong>Application:</strong> {{ ownership.application_name }}</li>
                    {% endif %}
                </ul>
            </div>
            
            {% if message %}
            <p><strong>Details:</strong> {{ message }}</p>
            {% endif %}
            
            <p>The certificate has been automatically renewed and is ready for use.</p>
        </div>
        
        <div class="footer">
            <p>This is an automated message from SSL Certificate Manager</p>
        </div>
    </div>
</body>
</html>
        """
        return Template(template_str)
    
    def _get_renewal_failure_template(self) -> Template:
        """Get email template for failed renewals."""
        template_str = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>SSL Certificate Renewal Failed</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #f44336; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background-color: #f9f9f9; }
        .cert-details { background-color: white; padding: 15px; margin: 10px 0; border-left: 4px solid #f44336; }
        .footer { text-align: center; padding: 20px; font-size: 12px; color: #666; }
        .error { color: #f44336; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>❌ SSL Certificate Renewal Failed</h1>
        </div>
        
        <div class="content">
            <p>Hello {{ ownership.owner_username or 'Certificate Owner' }},</p>
            
            <p class="error">The automatic renewal of your SSL certificate has failed.</p>
            
            <div class="cert-details">
                <h3>Certificate Details:</h3>
                <ul>
                    <li><strong>Common Name:</strong> {{ common_name }}</li>
                    <li><strong>File Path:</strong> {{ file_path }}</li>
                    {% if ownership.application_name %}
                    <li><strong>Application:</strong> {{ ownership.application_name }}</li>
                    {% endif %}
                </ul>
            </div>
            
            {% if message %}
            <p><strong>Error Details:</strong> {{ message }}</p>
            {% endif %}
            
            <p><strong>Action Required:</strong> Please manually renew this certificate or contact your system administrator for assistance.</p>
        </div>
        
        <div class="footer">
            <p>This is an automated message from SSL Certificate Manager</p>
        </div>
    </div>
</body>
</html>
        """
        return Template(template_str)
    
    def _html_to_text(self, html: str) -> str:
        """Convert HTML email to plain text."""
        # Simple HTML to text conversion
        import re
        
        # Remove HTML tags
        text = re.sub('<[^<]+?>', '', html)
        
        # Clean up whitespace
        text = re.sub(r'\n\s*\n', '\n\n', text)
        text = re.sub(r' +', ' ', text)
        
        return text.strip()
    
    def test_email_configuration(self) -> Dict:
        """Test email configuration by sending a test email."""
        test_email = self.email_config.get('username')
        if not test_email:
            return {'success': False, 'error': 'No test email configured'}
        
        try:
            success = self._send_email(
                to_email=test_email,
                subject='SSL Manager - Email Configuration Test',
                html_body='<p>This is a test email from SSL Certificate Manager.</p>',
                text_body='This is a test email from SSL Certificate Manager.'
            )
            
            return {
                'success': success,
                'message': 'Test email sent successfully' if success else 'Failed to send test email'
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
