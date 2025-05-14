import os
from typing import Dict, Any, Optional, Tuple
from .common import (
    logger, ENV, retry_with_backoff, EmailType, is_valid_arn,
    generate_timestamp, get_aws_clients, extract_base_secret_name
)
from .subscription_manager import SubscriptionManager

class NotificationManager:
    """
    Manages all user notifications and email communications
    """
    
    def __init__(self, subscription_manager=None):
        """
        Initialize NotificationManager
        
        Args:
            subscription_manager: Optional SubscriptionManager instance for testing
        """
        self.subscription_manager = subscription_manager or SubscriptionManager()
        self.region = ENV.get('REGION', 'us-east-1')
    
    def send_welcome_email(self, email_address: str, user_name: str) -> bool:
        """
        Send welcome email to user
        
        Args:
            email_address: Email to send to
            user_name: Username for personalization
            
        Returns:
            True if successful, False otherwise
        """
        subject = f'Welcome to AWS Access - Account Setup for {user_name}'
        
        message = (
            f"Hello {user_name},\n\n"
            f"Welcome! Your AWS account has been set up. "
            f"You will soon receive another email with instructions on how to access your AWS credentials.\n\n"
            f"Please note that you need to confirm your email subscription first by clicking the link "
            f"in the confirmation email you received. If you don't confirm your email subscription, "
            f"you won't receive important notifications about your AWS access.\n\n"
            f"If you have any questions, please contact your system administrator.\n\n"
            f"Thank you,\n"
            f"AWS Key Management System"
        )
        
        response = self.subscription_manager.send_notification(
            email_address=email_address,
            subject=subject,
            message=message,
            message_type=EmailType.WELCOME
        )
        
        return response is not None
    
    def send_credentials_email(self, email_address: str, user_name: str, secret_arn: str) -> bool:
        """
        Send email with credentials access information
        
        Args:
            email_address: Email to send to
            user_name: Username for personalization
            secret_arn: ARN of secret containing credentials
            
        Returns:
            True if successful, False otherwise
        """
        if not is_valid_arn(secret_arn) and not secret_arn.startswith('user-'):
            logger.error(f"Invalid secret ARN format: {secret_arn}")
            return False
            
        # Extract clean secret name for URL using the utility function
        secret_name = extract_base_secret_name(secret_arn, user_name)
            
        # Generate console URL with cleaned name
        secret_url = f"https://{self.region}.console.aws.amazon.com/secretsmanager/secret?name={secret_name}&region={self.region}"
        
        subject = f'Your AWS Credentials Are Ready - {user_name}'
        
        message = (
            f"Hello {user_name},\n\n"
            f"Your AWS access credentials are now available. "
            f"You can access your credentials using the link below:\n\n"
            f"{secret_url}\n\n"
            f"Important Security Notes:\n"
            f"1. These credentials provide access to AWS resources. Keep them secure and do not share them.\n"
            f"2. Credentials will automatically rotate every 90 days. You will be notified before rotation occurs.\n"
            f"3. If you suspect your credentials have been compromised, contact your administrator immediately.\n\n"
            f"If you have any questions, please contact your system administrator.\n\n"
            f"Thank you,\n"
            f"AWS Key Management System"
        )
        
        response = self.subscription_manager.send_notification(
            email_address=email_address,
            subject=subject,
            message=message,
            message_type=EmailType.CREDENTIALS
        )
        
        return response is not None
    
    def send_rotation_notice(self, email_address: str, user_name: str, secret_arn: str, days_remaining: int) -> bool:
        """
        Send notification about upcoming credential rotation
        
        Args:
            email_address: Email to send to
            user_name: Username for personalization
            secret_arn: ARN of secret being rotated
            days_remaining: Days until rotation
            
        Returns:
            True if successful, False otherwise
        """
        # Extract clean secret name for URL using the utility function
        secret_name = extract_base_secret_name(secret_arn, user_name)
            
        # Generate console URL with cleaned name
        secret_url = f"https://{self.region}.console.aws.amazon.com/secretsmanager/secret?name={secret_name}&region={self.region}"
        
        subject = f'Your AWS Access Key Will Rotate in {days_remaining} Days'
        
        message = (
            f"Hello {user_name},\n\n"
            f"Your AWS access key is scheduled to be automatically rotated in {days_remaining} days "
            f"as part of our security policy.\n\n"
            f"When rotation occurs:\n"
            f"1. A new access key will be created for your account\n"
            f"2. Your old access key will be deactivated\n"
            f"3. You will receive another notification when the rotation is complete\n\n"
            f"Your current key will remain active until the rotation date. To view your current credentials, visit:\n"
            f"{secret_url}\n\n"
            f"If you have any questions or need assistance, please contact the system administrator.\n\n"
            f"Thank you,\n"
            f"AWS Key Management System"
        )
        
        response = self.subscription_manager.send_notification(
            email_address=email_address,
            subject=subject,
            message=message,
            message_type=EmailType.ROTATION_NOTICE
        )
        
        return response is not None
    
    def send_rotation_complete_notice(self, email_address: str, user_name: str, secret_arn: str) -> bool:
        """
        Send notification that credential rotation is complete
        
        Args:
            email_address: Email to send to
            user_name: Username for personalization
            secret_arn: ARN of secret that was rotated
            
        Returns:
            True if successful, False otherwise
        """
        # Extract clean secret name for URL using the utility function
        secret_name = extract_base_secret_name(secret_arn, user_name)
            
        # Generate console URL with cleaned name
        secret_url = f"https://{self.region}.console.aws.amazon.com/secretsmanager/secret?name={secret_name}&region={self.region}"
        
        subject = f'Your AWS Access Key Has Been Rotated'
        
        message = (
            f"Hello {user_name},\n\n"
            f"Your AWS access key has been automatically rotated as part of our security policy.\n\n"
            f"The new access key is now active and available in AWS Secrets Manager. "
            f"Your old access key has been deactivated.\n\n"
            f"To access your new credentials, please visit:\n"
            f"{secret_url}\n\n"
            f"If you have any applications or scripts using the old credentials, "
            f"they will need to be updated with the new credentials.\n\n"
            f"If you have any questions or need assistance, please contact the system administrator.\n\n"
            f"Thank you,\n"
            f"AWS Key Management System"
        )
        
        response = self.subscription_manager.send_notification(
            email_address=email_address,
            subject=subject,
            message=message,
            message_type="rotation_complete"
        )
        
        return response is not None
    
    def send_manual_confirmation_email(self, email_address: str, user_name: str) -> bool:
        """
        Send email with manual confirmation instructions
        
        Args:
            email_address: Email to send to
            user_name: Username for personalization
            
        Returns:
            True if successful, False otherwise
        """
        subject = f'Action Required: Confirm Your AWS Notifications Subscription'
        
        message = (
            f"Hello {user_name},\n\n"
            f"We noticed that your AWS notification subscription was not confirmed or has expired. "
            f"A new subscription has been created, and you should receive a confirmation email shortly.\n\n"
            f"IMPORTANT: You must confirm this subscription to receive important notifications about your AWS access, "
            f"including credential information and rotation notices.\n\n"
            f"Please check your inbox for an email from AWS Notifications (no-reply@sns.amazonaws.com) and click the 'Confirm subscription' link.\n\n"
            f"If you don't see the confirmation email within a few minutes, please check your spam folder or contact your system administrator.\n\n"
            f"Thank you,\n"
            f"AWS Key Management System"
        )
        
        response = self.subscription_manager.send_notification(
            email_address=email_address,
            subject=subject,
            message=message,
            message_type=EmailType.MANUAL_CONFIRMATION
        )
        
        return response is not None
    
    def send_expired_confirmation_admin_notice(self, user_records: list) -> bool:
        """
        Send admin notification about users with expired confirmations
        
        Args:
            user_records: List of user records with expired confirmations
            
        Returns:
            True if successful, False otherwise
        """
        # Get admin email from environment or use a default
        admin_email = ENV.get('ADMIN_EMAIL')
        
        if not admin_email:
            logger.error("No admin email specified in environment, cannot send admin notice")
            return False
            
        subject = f'AWS Notification: {len(user_records)} Users with Expired Confirmation Links'
        
        message_lines = [
            "The following users have expired confirmation links and need manual intervention:",
            ""
        ]
        
        for i, user in enumerate(user_records, 1):
            user_name = user.get('user_name', 'Unknown')
            email = user.get('email_address', 'Unknown')
            created_at = user.get('created_at', 'Unknown')
            message_lines.append(f"{i}. User: {user_name}, Email: {email}, Created: {created_at}")
            
        message_lines.extend([
            "",
            "To resolve, use the admin interface to refresh the users' subscriptions,",
            "or run the manual subscription refresh Lambda function.",
            "",
            "This is an automated message from the AWS Subscription Management System."
        ])
        
        message = "\n".join(message_lines)
        
        response = self.subscription_manager.send_notification(
            email_address=admin_email,
            subject=subject,
            message=message,
            message_type="admin_notice"
        )
        
        return response is not None
